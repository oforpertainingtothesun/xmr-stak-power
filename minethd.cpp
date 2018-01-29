/*
  * This program is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
  * GNU General Public License for more details.
  *
  * You should have received a copy of the GNU General Public License
  * along with this program.  If not, see <http://www.gnu.org/licenses/>.
  *
  * Additional permission under GNU GPL version 3 section 7
  *
  * If you modify this Program, or any covered work, by linking or combining
  * it with OpenSSL (or a modified version of that library), containing parts
  * covered by the terms of OpenSSL License and SSLeay License, the licensors
  * of this Program grant you additional permission to convey the resulting
 * work.
  *
  */

#include "console.h"
#include <assert.h>
#include <bitset>
#include <chrono>
#include <cmath>
#include <cstring>
#include <map>
#include <stdio.h>
#include <thread>
#ifdef _WIN32
#include <windows.h>

void thd_setaffinity(std::thread::native_handle_type h, uint64_t cpu_id) {
  SetThreadAffinityMask(h, 1ULL << cpu_id);
}
#else
#include <pthread.h>

#if defined(__APPLE__)
#include <mach/thread_act.h>
#include <mach/thread_policy.h>
#define SYSCTL_CORE_COUNT "machdep.cpu.core_count"
#elif defined(__FreeBSD__)
#include <pthread_np.h>
#endif

void thd_setaffinity(std::thread::native_handle_type h, uint64_t cpu_id) {
#if defined(__APPLE__)
  thread_port_t mach_thread;
  thread_affinity_policy_data_t policy = {static_cast<integer_t>(cpu_id)};
  mach_thread = pthread_mach_thread_np(h);
  thread_policy_set(mach_thread, THREAD_AFFINITY_POLICY,
                    (thread_policy_t)&policy, 1);
#elif defined(__FreeBSD__)
  cpuset_t mn;
  CPU_ZERO(&mn);
  CPU_SET(cpu_id, &mn);
  pthread_setaffinity_np(h, sizeof(cpuset_t), &mn);
#elif !defined(__sun)
  cpu_set_t mn;
  CPU_ZERO(&mn);
  CPU_SET(cpu_id, &mn);
  pthread_setaffinity_np(h, sizeof(cpu_set_t), &mn);
#endif
}
#endif // _WIN32

#include "crypto/cryptonight.hpp"
#include "executor.h"
#include "hwlocMemory.hpp"
#include "jconf.h"
#include "minethd.h"

#ifdef __x86_64
#include "cryptonight_aesni.hpp"
#elif __PPC__
#include "cryptonight_altivec.hpp"
#else
#include "cryptonight_sparc.hpp"
#endif

telemetry::telemetry(size_t iThd) {
  ppHashCounts = new uint64_t *[iThd];
  ppTimestamps = new uint64_t *[iThd];
  iBucketTop = new uint32_t[iThd];

  for (size_t i = 0; i < iThd; i++) {
    ppHashCounts[i] = new uint64_t[iBucketSize];
    ppTimestamps[i] = new uint64_t[iBucketSize];
    iBucketTop[i] = 0;
    memset(ppHashCounts[0], 0, sizeof(uint64_t) * iBucketSize);
    memset(ppTimestamps[0], 0, sizeof(uint64_t) * iBucketSize);
  }
}

double telemetry::calc_telemetry_data(size_t iLastMilisec, size_t iThread) {
  using namespace std::chrono;
  uint64_t iTimeNow =
      time_point_cast<milliseconds>(high_resolution_clock::now())
          .time_since_epoch()
          .count();

  uint64_t iEarliestHashCnt = 0;
  uint64_t iEarliestStamp = 0;
  uint64_t iLastestStamp = 0;
  uint64_t iLastestHashCnt = 0;
  char bHaveFullSet = 0;

  // Start at 1, buckettop points to next empty
  for (size_t i = 1; i < iBucketSize; i++) {
    size_t idx =
        (iBucketTop[iThread] - i) & iBucketMask; // overflow expected here

    if (ppTimestamps[iThread][idx] == 0)
      break; // That means we don't have the data yet

    if (iLastestStamp == 0) {
      iLastestStamp = ppTimestamps[iThread][idx];
      iLastestHashCnt = ppHashCounts[iThread][idx];
    }

    if (iTimeNow - ppTimestamps[iThread][idx] > iLastMilisec) {
      bHaveFullSet = true;
      break; // We are out of the requested time period
    }

    iEarliestStamp = ppTimestamps[iThread][idx];
    iEarliestHashCnt = ppHashCounts[iThread][idx];
  }

  if (!bHaveFullSet || iEarliestStamp == 0 || iLastestStamp == 0)
    return nan("");

  // Don't think that can happen, but just in case
  if (iLastestStamp - iEarliestStamp == 0)
    return nan("");

  double fHashes, fTime;
  fHashes = iLastestHashCnt - iEarliestHashCnt;
  fTime = iLastestStamp - iEarliestStamp;
  fTime /= 1000.0;

  return fHashes / fTime;
}

void telemetry::push_perf_value(size_t iThd, uint64_t iHashCount,
                                uint64_t iTimestamp) {
  size_t iTop = iBucketTop[iThd];
  ppHashCounts[iThd][iTop] = iHashCount;
  ppTimestamps[iThd][iTop] = iTimestamp;

  iBucketTop[iThd] = (iTop + 1) & iBucketMask;
}

std::unique_ptr<cryptonight::Cryptonight> make_context() {
  using type = std::unique_ptr<cryptonight::Cryptonight>;
  if (jconf::inst()->HaveHardwareAes()) {
#ifdef __x86_64
    return type(new cryptonight::CryptonightAESNI);
#elif __PPC__
    return type(new cryptonight::CryptonightAltivec);
#else
    return type(new cryptonight::CryptonightSparc);
#endif
  }
  return type(new cryptonight::Cryptonight);
}

minethd::minethd(miner_work &pWork, size_t iNo, char double_work,
                 char no_prefetch, int64_t affinity) {
  oWork = pWork;
  bQuit = 0;
  iThreadNo = (uint8_t)iNo;
  iJobNo = 0;
  iHashCount = 0;
  iTimestamp = 0;
  bNoPrefetch = no_prefetch;
  this->affinity = affinity;

  if (double_work)
    oWorkThd = std::thread(&minethd::double_work_main, this);
  else
    oWorkThd = std::thread(&minethd::work_main, this);
}

std::atomic<uint64_t> minethd::iGlobalJobNo;
std::atomic<uint64_t>
    minethd::iConsumeCnt; // Threads get jobs as they are initialized
minethd::miner_work minethd::oGlobalWork;
uint64_t minethd::iThreadCount = 0;

char minethd::self_test() {
  size_t res;
  char fatal = false;

  auto ctx0 = make_context();

  auto out1 = ctx0->calculateResult(
      reinterpret_cast<const uint8_t *>("This is a test"), 14);
  auto bResult = memcmp(out1, "\xa0\x84\xf0\x1d\x14\x37\xa0\x9c\x69\x85\x40\x1b"
                              "\x60\xd4\x35\x54\xae\x10\x58\x02\xc5\xf5\xd8\xa9"
                              "\xb3\x25\x36\x49\xc0\xbe\x66\x05",
                        32) == 0;
  //  printf("result: %d\n",bResult);
  //	  for (int i = 0; i < 64; ++i) printf("%02x ",out[i]);
  //  printf("\n");

  if (!bResult)
    printer::inst()->print_msg(L0, "Cryptonight hash self-test failed. This "
                                   "might be caused by bad compiler "
                                   "optimizations.");
  return bResult;
}

std::map<int, minethd *> *minethd::thread_starter(miner_work &pWork) {
  iGlobalJobNo = 0;
  iConsumeCnt = 0;
  std::map<int, minethd *> *pvThreads = new std::map<int, minethd *>;

  // Launch the requested number of single and double threads, to distribute
  // load evenly we need to alternate single and double threads
  size_t i, n = jconf::inst()->GetThreadCount();

  jconf::thd_cfg cfg;
  for (i = 0; i < n; i++) {
    jconf::inst()->GetThreadConfig(i, cfg);

    minethd *thd =
        new minethd(pWork, i, cfg.bDoubleMode, cfg.bNoPrefetch, cfg.iCpuAff);
    (*pvThreads)[i] = thd;

    if (cfg.iCpuAff >= 0)
      printer::inst()->print_msg(L1, "Starting %s thread, affinity: %d.",
                                 cfg.bDoubleMode ? "double" : "single",
                                 (int)cfg.iCpuAff);
    else
      printer::inst()->print_msg(L1, "Starting %s thread, no affinity.",
                                 cfg.bDoubleMode ? "double" : "single");
  }

  iThreadCount = n;
  return pvThreads;
}

void minethd::switch_work(miner_work &pWork) {
  // iConsumeCnt is a basic lock-like polling mechanism just in case we happen
  // to push work
  // faster than threads can consume them. This should never happen in real
  // life.
  // Pool cant physically send jobs faster than every 250ms or so due to net
  // latency.

  while (iConsumeCnt.load(std::memory_order_seq_cst) < iThreadCount)
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

  oGlobalWork = pWork;
  iConsumeCnt.store(0, std::memory_order_seq_cst);
  iGlobalJobNo++;
}

void minethd::consume_work() {
  memcpy(&oWork, &oGlobalWork, sizeof(miner_work));
  iJobNo++;
  iConsumeCnt++;
}

void minethd::pin_thd_affinity() {
  // pin memory to NUMA node
  bindMemoryToNUMANode(affinity);

#if defined(__APPLE__)
  printer::inst()->print_msg(
      L1, "WARNING on MacOS thread affinity is only advisory.");
#endif
  thd_setaffinity(oWorkThd.native_handle(), affinity);
}

void minethd::work_main() {
  if (affinity >= 0) //-1 means no affinity
    pin_thd_affinity();

  auto ctx = make_context();
  uint64_t iCount = 0;
  uint32_t *piNonce;
  job_result result;

  piNonce = (uint32_t *)(oWork.bWorkBlob + 39);
  iConsumeCnt++;

  while (bQuit == 0) {
    if (oWork.bStall) {
      /*  We are stalled here because the executor didn't find a job for us yet,
          either because of network latency, or a socket problem. Since we are
          raison d'etre of this software it us sensible to just wait until we
         have something*/

      while (iGlobalJobNo.load(std::memory_order_relaxed) == iJobNo)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

      consume_work();
      continue;
    }

    if (oWork.bNiceHash)
      result.iNonce = calc_nicehash_nonce(*piNonce, oWork.iResumeCnt);
    else
      result.iNonce = calc_start_nonce(oWork.iResumeCnt);

    assert(sizeof(job_result::sJobID) == sizeof(pool_job::sJobID));
    memcpy(result.sJobID, oWork.sJobID, sizeof(job_result::sJobID));

    while (iGlobalJobNo.load(std::memory_order_relaxed) == iJobNo) {
      if ((iCount & 0xF) == 0) // Store stats every 16 hashes
      {
        using namespace std::chrono;
        uint64_t iStamp =
            time_point_cast<milliseconds>(high_resolution_clock::now())
                .time_since_epoch()
                .count();
        iHashCount.store(iCount, std::memory_order_relaxed);
        iTimestamp.store(iStamp, std::memory_order_relaxed);
      }
      iCount++;

      *piNonce = ++result.iNonce;

      auto out = ctx->calculateResult(oWork.bWorkBlob, oWork.iWorkSize);

      uint64_t *piHashVal = reinterpret_cast<uint64_t *>(out + 24);
      if (*piHashVal < oWork.iTarget) {
        memcpy(result.bResult, out, sizeof(out));
        executor::inst()->push_event(ex_event(result, oWork.iPoolId));
      }

      std::this_thread::yield();
    }

    consume_work();
  }
}

void minethd::double_work_main() {
  if (affinity >= 0) //-1 means no affinity
    pin_thd_affinity();

  auto ctx0 = make_context();
  auto ctx1 = make_context();
  uint64_t iCount = 0;
  uint32_t *piNonce0, *piNonce1;
  uint8_t bDoubleHashOut[64];
  uint8_t bDoubleWorkBlob[sizeof(miner_work::bWorkBlob) * 2];
  uint32_t iNonce;
  job_result res;

  piNonce0 = (uint32_t *)(bDoubleWorkBlob + 39);
  piNonce1 = nullptr;

  iConsumeCnt++;

  while (bQuit == 0) {
    if (oWork.bStall) {
      /*	We are stalled here because the executor didn't find a job for
      us yet,
      either because of network latency, or a socket problem. Since we are
      raison d'etre of this software it us sensible to just wait until we have
      something*/

      while (iGlobalJobNo.load(std::memory_order_relaxed) == iJobNo)
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

      consume_work();
      memcpy(bDoubleWorkBlob, oWork.bWorkBlob, oWork.iWorkSize);
      memcpy(bDoubleWorkBlob + oWork.iWorkSize, oWork.bWorkBlob,
             oWork.iWorkSize);
      piNonce1 = (uint32_t *)(bDoubleWorkBlob + oWork.iWorkSize + 39);
      continue;
    }

    if (oWork.bNiceHash)
      iNonce = calc_nicehash_nonce(*piNonce0, oWork.iResumeCnt);
    else
      iNonce = calc_start_nonce(oWork.iResumeCnt);

    assert(sizeof(job_result::sJobID) == sizeof(pool_job::sJobID));

    while (iGlobalJobNo.load(std::memory_order_relaxed) == iJobNo) {
      if ((iCount & 0x7) == 0) // Store stats every 16 hashes
      {
        using namespace std::chrono;
        uint64_t iStamp =
            time_point_cast<milliseconds>(high_resolution_clock::now())
                .time_since_epoch()
                .count();
        iHashCount.store(iCount, std::memory_order_relaxed);
        iTimestamp.store(iStamp, std::memory_order_relaxed);
      }

      iCount += 2;

      *piNonce0 = ++iNonce;
      *piNonce1 = ++iNonce;

      // TODO: Implement the double or more hashing
      auto out0 = ctx0->calculateResult(bDoubleWorkBlob, oWork.iWorkSize);
      auto out1 = ctx1->calculateResult(bDoubleWorkBlob + oWork.iWorkSize,
                                        oWork.iWorkSize);

      uint64_t *piHashVal0 = reinterpret_cast<uint64_t *>(out0 + 24);
      if (*piHashVal0 < oWork.iTarget) {
        executor::inst()->push_event(ex_event(
            job_result(oWork.sJobID, iNonce - 1, out0), oWork.iPoolId));
      }
      uint64_t *piHashVal1 = reinterpret_cast<uint64_t *>(out1 + 24);
      if (*piHashVal1 < oWork.iTarget) {
        executor::inst()->push_event(
            ex_event(job_result(oWork.sJobID, iNonce, out1), oWork.iPoolId));
      }

      std::this_thread::yield();
    }

    consume_work();
    memcpy(bDoubleWorkBlob, oWork.bWorkBlob, oWork.iWorkSize);
    memcpy(bDoubleWorkBlob + oWork.iWorkSize, oWork.bWorkBlob, oWork.iWorkSize);
    piNonce1 = (uint32_t *)(bDoubleWorkBlob + oWork.iWorkSize + 39);
  }
}
