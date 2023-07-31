// Copyright (c) 2017, Tencent Inc.
// All rights reserved.
//
// Author: sevenyou <sevenyou@tencent.com>
// Created: 07/17/17
// Description:

#include "response/base_resp.h"

#include <stdio.h>
#include <string.h>

#include <iostream>

#include "cos_params.h"
#include "cos_sys_config.h"
#include "rapidxml/1.13/rapidxml.hpp"
#include "rapidxml/1.13/rapidxml_print.hpp"
#include "rapidxml/1.13/rapidxml_utils.hpp"
#include "util/string_util.h"

namespace qcloud_cos {

std::string BaseResp::GetHeader(const std::string& key) const {
  std::map<std::string, std::string>::const_iterator itr = m_headers.find(key);
  if (itr != m_headers.end()) {
    return itr->second;
  }

  return "";
}

void BaseResp::ParseFromHeaders(
    const std::map<std::string, std::string>& headers) {
  m_headers = headers;
  // TODO 可以直接从get hreader，不需要parse
  #if 0
  std::map<std::string, std::string>::const_iterator itr;
  itr = headers.find(kHttpHeaderContentLength);
  if (headers.end() != itr) {
    m_content_length = StringUtil::StringToUint64(itr->second);
  }

  itr = headers.find(kHttpHeaderContentRange);
  if (headers.end() != itr) {
    m_content_range = StringUtil::StringToUint64(itr->second);
  }

  itr = headers.find(kHttpHeaderContentType);
  if (headers.end() != itr) {
    m_content_type = itr->second;
  }

  itr = headers.find(kHttpHeaderEtag);
  if (headers.end() != itr) {
    m_etag = StringUtil::Trim(itr->second, "\"");
  } else {
    // 某些代理软件可能会修改HTTP Header，比如把ETag改成Etag
    // 此处找不到ETag，再尝试查找Etag
    itr = headers.find(kHttpHeaderLowerCaseEtag);
    if (headers.end() != itr) {
      m_etag = StringUtil::Trim(itr->second, "\"");
    }
  }

  itr = headers.find(kHttpHeaderConnection);
  if (headers.end() != itr) {
    m_connection = itr->second;
  }

  itr = headers.find(kHttpHeaderDate);
  if (headers.end() != itr) {
    m_date = itr->second;
  }

  itr = headers.find(kHttpHeaderServer);
  if (headers.end() != itr) {
    m_server = itr->second;
  }

  itr = headers.find(kHttpHeaderContentDisposition);
  if (headers.end() != itr) {
    m_content_disposition = itr->second;
  }

  itr = headers.find(kHttpHeaderContentEncoding);
  if (headers.end() != itr) {
    m_content_encoding = itr->second;
  }

  itr = headers.find(kHttpHeaderCacheControl);
  if (headers.end() != itr) {
    m_cache_control = itr->second;
  }

  itr = headers.find(kHttpHeaderExpires);
  if (headers.end() != itr) {
    m_expires = itr->second;
  }

  itr = headers.find(kHttpHeaderLastModified);
  if (headers.end() != itr) {
    m_last_modified = itr->second;
  }

  itr = headers.find(kRespHeaderXCosHashCrc64Ecma);
  if (headers.end() != itr) {
    m_x_cos_hash_crc64ecma = itr->second;
  }

  itr = headers.find(kRespHeaderXCosReqId);
  if (headers.end() != itr) {
    m_x_cos_request_id = itr->second;
  }

  itr = headers.find(kRespHeaderXCosTraceId);
  if (headers.end() != itr) {
    m_x_cos_trace_id = itr->second;
  }

  itr = headers.find(kRespHeaderXCosStorageClass);
  if (headers.end() != itr) {
    m_x_cos_storage_class = itr->second;
  }

  itr = headers.find(kRespHeaderXCosStorageTier);
  if (headers.end() != itr) {
    m_x_cos_storage_tier = itr->second;
  }
  #endif
}

bool BaseResp::ParseFromACLXMLString(const std::string& body,
                                     std::string* owner_id,
                                     std::string* owner_display_name,
                                     std::vector<Grant>* acl) {
  std::string tmp_body = body;
  rapidxml::xml_document<> doc;

  if (!StringUtil::StringToXml(&tmp_body[0], &doc)) {
    SDK_LOG_ERR("Parse string to xml doc error, xml_body=%s", body.c_str());
    return false;
  }

  rapidxml::xml_node<>* root = doc.first_node("AccessControlPolicy");
  if (NULL == root) {
    SDK_LOG_ERR("Miss root node=AccessControlPolicy, xml_body=%s",
                body.c_str());
    return false;
  }

  rapidxml::xml_node<>* node = root->first_node();
  for (; node != NULL; node = node->next_sibling()) {
    const std::string node_name = node->name();
    if ("Owner" == node_name) {
      rapidxml::xml_node<>* owner_node = node->first_node();
      for (; owner_node != NULL; owner_node = owner_node->next_sibling()) {
        const std::string owner_node_name = owner_node->name();
        if ("ID" == owner_node_name) {
          *owner_id = owner_node->value();
        } else if ("DisplayName" == owner_node_name) {
          *owner_display_name = owner_node->value();
        } else {
          SDK_LOG_WARN("Unknown field in owner node, field_name=%s",
                       owner_node_name.c_str());
        }
      }
    } else if ("AccessControlList" == node_name) {
      rapidxml::xml_node<>* acl_node = node->first_node();
      for (; acl_node != NULL; acl_node = acl_node->next_sibling()) {
        const std::string acl_node_name = acl_node->name();
        if ("Grant" == acl_node_name) {
          Grant grant;
          rapidxml::xml_node<>* grant_node = acl_node->first_node();
          for (; grant_node != NULL; grant_node = grant_node->next_sibling()) {
            const std::string& grant_node_name = grant_node->name();
            if ("Grantee" == grant_node_name) {
              rapidxml::xml_attribute<>* type_attr =
                  grant_node->first_attribute("xsi:type");
              if (type_attr != NULL) {
                grant.m_grantee.m_type = type_attr->value();
              }
              rapidxml::xml_node<>* grantee_node = grant_node->first_node();
              for (; grantee_node != NULL;
                   grantee_node = grantee_node->next_sibling()) {
                const std::string& grantee_node_name = grantee_node->name();
                if ("ID" == grantee_node_name) {
                  grant.m_grantee.m_id = grantee_node->value();
                } else if ("DisplayName" == grantee_node_name) {
                  grant.m_grantee.m_display_name = grantee_node->value();
                } else if ("URI" == grantee_node_name) {
                  // TODO(sevenyou) 公有读写才返回URI
                  grant.m_grantee.m_uri = grantee_node->value();
                } else {
                  SDK_LOG_WARN("Unknown field in grantee node, field_name=%s",
                               grantee_node_name.c_str());
                }
              }
            } else if ("Permission" == grant_node_name) {
              grant.m_perm = grant_node->value();
            } else {
              SDK_LOG_WARN("Unknown field in grant node, field_name=%s",
                           grant_node_name.c_str());
            }
          }
          acl->push_back(grant);
        } else {
          SDK_LOG_WARN("Unknown field in AccessControlList node, field_name=%s",
                       acl_node_name.c_str());
        }
      }
    } else {
      SDK_LOG_WARN("Unknown field in AccessControlPolicy node, field_name=%s",
                   node_name.c_str());
    }
  }

  return true;
}

void BaseResp::InternalCopyFrom(const BaseResp& resp) {
  m_headers = resp.m_headers;
  m_body_str = resp.m_body_str;
  m_content_length = resp.m_content_length;
  m_content_type = resp.m_content_type;
  m_etag = resp.m_etag;
  m_connection = resp.m_connection;
  m_date = resp.m_date;
  m_server = resp.m_server;
  m_content_disposition = resp.m_content_disposition;
  m_content_encoding = resp.m_content_encoding;
  m_cache_control = resp.m_cache_control;
  m_expires = resp.m_expires;
  m_last_modified = resp.m_last_modified;
  m_x_cos_request_id = resp.m_x_cos_request_id;
  m_x_cos_trace_id = resp.m_x_cos_trace_id;
  m_x_cos_storage_tier = resp.m_x_cos_storage_tier;
  m_x_cos_storage_class = resp.m_x_cos_storage_class;
  m_x_cos_hash_crc64ecma = resp.m_x_cos_hash_crc64ecma;
}

}  // namespace qcloud_cos
