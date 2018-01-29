#pragma once

#include "rapidjson/document.h"
#include "rapidjson/rapidjson.h"

using namespace rapidjson;

/* This macro brings rapidjson more in line with other libs */
inline const Value *GetObjectMember(const Value &obj, const char *key) {
  Value::ConstMemberIterator itr = obj.FindMember(key);
  if (itr != obj.MemberEnd())
    return &itr->value;
  else
    return nullptr;
}
