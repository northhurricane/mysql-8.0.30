﻿// Copyright (c) 2017, Tencent Inc.
// All rights reserved.
//
// Author: sevenyou <sevenyou@tencent.com>
// Created: 07/25/17
// Description:

#include <sstream>

#include "Poco/MD5Engine.h"
#include "Poco/StreamCopier.h"
#include "cos_api.h"
#include "util/test_utils.h"
#include "util/file_util.h"
#include "util/simple_dns_cache.h"
#include "gtest/gtest.h"

/*
export CPP_SDK_V5_ACCESS_KEY=xxx
export CPP_SDK_V5_SECRET_KEY=xxx
export CPP_SDK_V5_REGION=ap-guangzhou
export CPP_SDK_V5_UIN=xxx
export CPP_SDK_V5_APPID=xxx
export COS_CPP_V5_TAG=""
export COS_CPP_V5_USE_DNS_CACHE="true"

export CPP_SDK_V5_OTHER_ACCESS_KEY=xxx
export CPP_SDK_V5_OTHER_SECRET_KEY=xxx
export CPP_SDK_V5_OTHER_REGION=ap-hongkong
export CPP_SDK_V5_OTHER_UIN=xxx
*/

namespace qcloud_cos {

class ObjectOpTest : public testing::Test {
 protected:
  static void SetUpTestCase() {
    std::cout << "================SetUpTestCase Begin===================="
              << std::endl;
    m_config = new CosConfig("./config.json");
    m_config->SetAccessKey(GetEnvVar("CPP_SDK_V5_ACCESS_KEY"));
    m_config->SetSecretKey(GetEnvVar("CPP_SDK_V5_SECRET_KEY"));
    m_config->SetRegion(GetEnvVar("CPP_SDK_V5_REGION"));
    if (GetEnvVar("COS_CPP_V5_USE_DNS_CACHE") == "true") {
      std::cout << "================USE DNS CACHE===================="
                << std::endl;
      CosSysConfig::SetUseDnsCache(true);
    }
    m_client = new CosAPI(*m_config);

    m_bucket_name = "coscppsdkv5ut" + GetEnvVar("COS_CPP_V5_TAG") + "-" +
                    GetEnvVar("CPP_SDK_V5_APPID");
    m_bucket_name2 = "coscppsdkv5utcopy" + GetEnvVar("COS_CPP_V5_TAG") + "-" +
                     GetEnvVar("CPP_SDK_V5_APPID");
    {
      PutBucketReq req(m_bucket_name);
      PutBucketResp resp;
      CosResult result = m_client->PutBucket(req, &resp);
      ASSERT_TRUE(result.IsSucc());
    }

    {
      PutBucketReq req(m_bucket_name2);
      PutBucketResp resp;
      CosResult result = m_client->PutBucket(req, &resp);
      ASSERT_TRUE(result.IsSucc());
    }

    std::cout << "================SetUpTestCase End===================="
              << std::endl;
  }

  static void TearDownTestCase() {
    std::cout << "================TearDownTestCase Begin===================="
              << std::endl;

    // 1. 删除所有Object
    {{GetBucketReq req(m_bucket_name);
    GetBucketResp resp;
    CosResult result = m_client->GetBucket(req, &resp);
    ASSERT_TRUE(result.IsSucc());

    const std::vector<Content>& contents = resp.GetContents();
    for (std::vector<Content>::const_iterator c_itr = contents.begin();
         c_itr != contents.end(); ++c_itr) {
      const Content& content = *c_itr;
      DeleteObjectReq del_req(m_bucket_name, content.m_key);
      DeleteObjectResp del_resp;
      CosResult del_result = m_client->DeleteObject(del_req, &del_resp);
      EXPECT_TRUE(del_result.IsSucc());
      if (!del_result.IsSucc()) {
        std::cout << "DeleteObject Failed, check object=" << content.m_key
                  << std::endl;
      }
    }
  }

  {
    GetBucketReq req(m_bucket_name2);
    GetBucketResp resp;
    CosResult result = m_client->GetBucket(req, &resp);
    ASSERT_TRUE(result.IsSucc());

    const std::vector<Content>& contents = resp.GetContents();
    for (std::vector<Content>::const_iterator c_itr = contents.begin();
         c_itr != contents.end(); ++c_itr) {
      const Content& content = *c_itr;
      DeleteObjectReq del_req(m_bucket_name2, content.m_key);
      DeleteObjectResp del_resp;
      CosResult del_result = m_client->DeleteObject(del_req, &del_resp);
      EXPECT_TRUE(del_result.IsSucc());
      if (!del_result.IsSucc()) {
        std::cout << "DeleteObject Failed, check object=" << content.m_key
                  << std::endl;
      }
    }
  }
}

// 2. 删除所有未complete的分块
{
  for (std::map<std::string, std::string>::const_iterator c_itr =
           m_to_be_aborted.begin();
       c_itr != m_to_be_aborted.end(); ++c_itr) {
    AbortMultiUploadReq req(m_bucket_name, c_itr->first, c_itr->second);
    AbortMultiUploadResp resp;

    CosResult result = m_client->AbortMultiUpload(req, &resp);
    EXPECT_TRUE(result.IsSucc());
    if (!result.IsSucc()) {
      std::cout << "AbortMultiUpload Failed, object=" << c_itr->first
                << ", upload_id=" << c_itr->second << std::endl;
    }
  }
}

{
  // 删除所有碎片
  std::vector<std::string> bucket_v = {m_bucket_name, m_bucket_name2};
  for (auto& bucket : bucket_v) {
    qcloud_cos::ListMultipartUploadReq list_mp_req(bucket);
    qcloud_cos::ListMultipartUploadResp list_mp_resp;
    qcloud_cos::CosResult list_mp_result =
        m_client->ListMultipartUpload(list_mp_req, &list_mp_resp);
    ASSERT_TRUE(list_mp_result.IsSucc());
    std::vector<Upload> rst = list_mp_resp.GetUpload();
    for (std::vector<qcloud_cos::Upload>::const_iterator itr = rst.begin();
         itr != rst.end(); ++itr) {
      AbortMultiUploadReq abort_mp_req(bucket, itr->m_key, itr->m_uploadid);
      AbortMultiUploadResp abort_mp_resp;
      CosResult abort_mp_result =
          m_client->AbortMultiUpload(abort_mp_req, &abort_mp_resp);
      EXPECT_TRUE(abort_mp_result.IsSucc());
      if (!abort_mp_result.IsSucc()) {
        std::cout << "AbortMultiUpload Failed, object=" << itr->m_key
                  << ", upload_id=" << itr->m_uploadid << std::endl;
      }
    }
  }
}

// 3. 删除Bucket
{
  {
    DeleteBucketReq req(m_bucket_name);
    DeleteBucketResp resp;
    CosResult result = m_client->DeleteBucket(req, &resp);
    ASSERT_TRUE(result.IsSucc());
  }

  {
    DeleteBucketReq req(m_bucket_name2);
    DeleteBucketResp resp;
    CosResult result = m_client->DeleteBucket(req, &resp);
    ASSERT_TRUE(result.IsSucc());
  }
}

delete m_client;
delete m_config;
std::cout << "================TearDownTestCase End===================="
          << std::endl;
}  // namespace qcloud_cos

protected:
static CosConfig* m_config;
static CosAPI* m_client;
static std::string m_bucket_name;
static std::string m_bucket_name2;  // 用于copy

// 用于记录单测中未Complete的分块上传uploadID,便于清理
static std::map<std::string, std::string> m_to_be_aborted;
}
;

std::string ObjectOpTest::m_bucket_name = "";
std::string ObjectOpTest::m_bucket_name2 = "";
CosConfig* ObjectOpTest::m_config = NULL;
CosAPI* ObjectOpTest::m_client = NULL;
std::map<std::string, std::string> ObjectOpTest::m_to_be_aborted;

#if 1

TEST_F(ObjectOpTest, PutObjectByFileTest) {
  // 1. ObjectName为普通字符串
  {
    std::string local_file = "./testfile";
    TestUtils::WriteRandomDatatoFile(local_file, 1024);
    PutObjectByFileReq req(m_bucket_name, "test_object", local_file);
    req.SetXCosStorageClass(kStorageClassStandard);
    PutObjectByFileResp resp;
    CosResult result = m_client->PutObject(req, &resp);
    ASSERT_TRUE(result.IsSucc());
    TestUtils::RemoveFile(local_file);
  }

  // 2. ObjectName为中文字符串
  {
    std::string local_file = "./testfile";
    TestUtils::WriteRandomDatatoFile(local_file, 1024);
    PutObjectByFileReq req(m_bucket_name, "这是个中文Object", local_file);
    req.SetXCosStorageClass(kStorageClassStandard);
    PutObjectByFileResp resp;
    CosResult result = m_client->PutObject(req, &resp);
    ASSERT_TRUE(result.IsSucc());
    TestUtils::RemoveFile(local_file);
  }

  // 3. ObjectName为特殊字符串
  {
    std::string local_file = "./testfile";
    TestUtils::WriteRandomDatatoFile(local_file, 1024);
    PutObjectByFileReq req(
        m_bucket_name,
        "/→↓←→↖↗↙↘! \"#$%&'()*+,-./0123456789:;"
        "<=>@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
        local_file);
    req.SetXCosStorageClass(kStorageClassStandardIA);
    PutObjectByFileResp resp;
    CosResult result = m_client->PutObject(req, &resp);
    ASSERT_TRUE(result.IsSucc());
    TestUtils::RemoveFile(local_file);
  }

  // 4. 上传下载各种不同大小的文件
  {
    // std::vector<int> base_size_v = {1024};
    std::vector<int> base_size_v = {5,    35,    356,         1024,
                                    2545, 25678, 1024 * 1024, 5 * 1024 * 1024};

    for (auto& size : base_size_v) {
      for (int i = 1; i < 10; i++) {
        std::cout << "base_size: " << size << ", test_time: " << i << std::endl;
        size_t file_size = ((rand() % 100) + 1) * size;
        std::string object_name = "test_object_" + std::to_string(file_size);
        std::string local_file = "./" + object_name;
        std::cout << "generate file: " << local_file << std::endl;
        TestUtils::WriteRandomDatatoFile(local_file, file_size);

        // 上传对象
        std::cout << "start to upload: " << local_file << std::endl;
        PutObjectByFileReq put_req(m_bucket_name, object_name, local_file);
        put_req.SetRecvTimeoutInms(1000 * 200);
        PutObjectByFileResp put_resp;
        CosResult put_result = m_client->PutObject(put_req, &put_resp);
        ASSERT_TRUE(put_result.IsSucc());

        // 校验文件
        std::string file_md5_origin = TestUtils::CalcFileMd5(local_file);
        ASSERT_EQ(put_resp.GetEtag(), file_md5_origin);

        // 下载对象
        std::cout << "start to download: " << object_name << std::endl;
        std::string file_download = local_file + "_download";
        GetObjectByFileReq get_req(m_bucket_name, object_name, file_download);
        GetObjectByFileResp get_resp;
        CosResult get_result = m_client->GetObject(get_req, &get_resp);
        ASSERT_TRUE(get_result.IsSucc());
        std::string file_md5_download = TestUtils::CalcFileMd5(file_download);
        ASSERT_EQ(file_md5_download, file_md5_origin);
        ASSERT_EQ(file_md5_download, get_resp.GetEtag());

        // 删除对象
        std::cout << "start to delete: " << object_name << std::endl;
        CosResult del_result;
        qcloud_cos::DeleteObjectReq del_req(m_bucket_name, object_name);
        qcloud_cos::DeleteObjectResp del_resp;
        del_result = m_client->DeleteObject(del_req, &del_resp);
        ASSERT_TRUE(del_result.IsSucc());

        // 删除本地文件
        TestUtils::RemoveFile(local_file);
        TestUtils::RemoveFile(file_download);
      }
    }
  }

  // 5. 服务端加密, 正确的加密算法AES256
  {
    std::istringstream iss("put_obj_by_stream_string");
    PutObjectByStreamReq req(m_bucket_name, "object_server_side_enc_test", iss);
    req.SetXCosStorageClass(kStorageClassStandard);
    req.SetXCosServerSideEncryption("AES256");
    PutObjectByStreamResp resp;
    CosResult result = m_client->PutObject(req, &resp);
    ASSERT_TRUE(result.IsSucc());
    EXPECT_EQ("AES256", resp.GetXCosServerSideEncryption());
  }

  // 6. 服务端加密, 错误的加密算法AES789
  {
    std::istringstream iss("put_obj_by_stream_string");
    PutObjectByStreamReq req(m_bucket_name, "object_server_side_enc_wrong_test",
                             iss);
    req.SetXCosStorageClass(kStorageClassStandard);
    req.SetXCosServerSideEncryption("AES789");
    PutObjectByStreamResp resp;
    CosResult result = m_client->PutObject(req, &resp);
    ASSERT_FALSE(result.IsSucc());
    EXPECT_EQ(400, result.GetHttpStatus());
    // EXPECT_EQ("SSEContentNotSupported", result.GetErrorCode());
    EXPECT_EQ("InvalidArgument", result.GetErrorCode());
  }

  // 7. 关闭MD5上传校验
  {
    std::istringstream iss("put_obj_by_stream_string");
    PutObjectByStreamReq req(m_bucket_name, "object_file_not_count_contentmd5",
                             iss);
    req.TurnOffComputeConentMd5();
    PutObjectByStreamResp resp;
    CosResult result = m_client->PutObject(req, &resp);
    ASSERT_TRUE(result.IsSucc());
  }
}

TEST_F(ObjectOpTest, PutObjectByStreamTest) {
  // 1. ObjectName为普通字符串
  {
    std::istringstream iss("put_obj_by_stream_normal_string");
    PutObjectByStreamReq req(m_bucket_name, "object_test2", iss);
    req.SetXCosStorageClass(kStorageClassStandard);
    PutObjectByStreamResp resp;
    CosResult result = m_client->PutObject(req, &resp);
    ASSERT_TRUE(result.IsSucc());
  }

  // 2. ObjectName为中文字符串
  {
    std::istringstream iss("put_obj_by_stream_chinese_string");
    PutObjectByStreamReq req(m_bucket_name, "这是个中文Object2", iss);
    req.SetXCosStorageClass(kStorageClassStandardIA);
    PutObjectByStreamResp resp;
    CosResult result = m_client->PutObject(req, &resp);
    ASSERT_TRUE(result.IsSucc());
  }

  // 3. ObjectName为特殊字符串
  {
    std::istringstream iss("put_obj_by_stream_special_string");
    PutObjectByStreamReq req(
        m_bucket_name,
        "/→↓←→↖↗↙↘! \"#$%&'()*+,-./0123456789:;"
        "<=>@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~2",
        iss);
    req.SetXCosStorageClass(kStorageClassStandard);
    PutObjectByStreamResp resp;
    CosResult result = m_client->PutObject(req, &resp);
    ASSERT_TRUE(result.IsSucc());
  }

  // 4. 关闭MD5上传校验
  {
    std::istringstream iss("put_obj_by_stream_not_count_contentmd5");
    PutObjectByStreamReq req(m_bucket_name, "object_test3", iss);
    req.TurnOffComputeConentMd5();
    PutObjectByStreamResp resp;
    CosResult result = m_client->PutObject(req, &resp);
    ASSERT_TRUE(result.IsSucc());
  }
}

TEST_F(ObjectOpTest, IsObjectExistTest) {
  std::istringstream iss("put_obj_by_stream_string");
  std::string object_name = "object_test";
  PutObjectByStreamReq req(m_bucket_name, object_name, iss);
  PutObjectByStreamResp resp;
  CosResult result = m_client->PutObject(req, &resp);
  ASSERT_TRUE(result.IsSucc());
  EXPECT_TRUE(m_client->IsObjectExist(m_bucket_name, object_name));
  EXPECT_FALSE(m_client->IsObjectExist(m_bucket_name, "not_exist_object"));
}

TEST_F(ObjectOpTest, HeadObjectTest) {
  {
    std::istringstream iss("put_obj_by_stream_normal_string");
    PutObjectByStreamReq put_req(m_bucket_name, "test_head_object", iss);
    PutObjectByStreamResp put_resp;
    CosResult result = m_client->PutObject(put_req, &put_resp);
    ASSERT_TRUE(result.IsSucc());

    HeadObjectReq head_req(m_bucket_name, "test_head_object");
    HeadObjectResp head_resp;
    result = m_client->HeadObject(head_req, &head_resp);
    ASSERT_TRUE(result.IsSucc());
  }

  {
    std::istringstream iss("put_obj_by_stream_normal_string");
    PutObjectByStreamReq put_req(m_bucket_name, "test_head_object_with_sse",
                                 iss);
    put_req.SetXCosServerSideEncryption("AES256");
    PutObjectByStreamResp put_resp;
    CosResult result = m_client->PutObject(put_req, &put_resp);
    ASSERT_TRUE(result.IsSucc());

    HeadObjectReq head_req(m_bucket_name, "test_head_object_with_sse");
    HeadObjectResp head_resp;
    result = m_client->HeadObject(head_req, &head_resp);
    ASSERT_TRUE(result.IsSucc());
    EXPECT_EQ("AES256", head_resp.GetXCosServerSideEncryption());
  }
}

TEST_F(ObjectOpTest, DeleteObjectTest) {
  {
    // Delete empty string, test whether call the DeleteBucket interface
    std::string object_name = "";
    DeleteObjectReq req(m_bucket_name, object_name);
    DeleteObjectResp resp;
    CosResult result = m_client->DeleteObject(req, &resp);
    std::string errinfo = result.GetErrorMsg();
    EXPECT_EQ("Delete object's name is empty.", errinfo);
  }
}

TEST_F(ObjectOpTest, GetObjectByFileTest) {
  {
    std::istringstream iss("put_obj_by_stream_normal_string");
    std::string object_name = "get_object_by_file_test";
    PutObjectByStreamReq put_req(m_bucket_name, object_name, iss);
    PutObjectByStreamResp put_resp;
    CosResult put_result = m_client->PutObject(put_req, &put_resp);
    ASSERT_TRUE(put_result.IsSucc());

    std::string file_download = "file_download";
    GetObjectByFileReq get_req(m_bucket_name, object_name, file_download);
    GetObjectByFileResp get_resp;
    CosResult get_result = m_client->GetObject(get_req, &get_resp);
    ASSERT_TRUE(get_result.IsSucc());

    std::string file_md5_download = TestUtils::CalcFileMd5(file_download);
    ASSERT_EQ(file_md5_download, get_resp.GetEtag());

    DeleteObjectReq del_req(m_bucket_name, object_name);
    DeleteObjectResp del_resp;
    CosResult del_result = m_client->DeleteObject(del_req, &del_resp);
    ASSERT_TRUE(del_result.IsSucc());

    TestUtils::RemoveFile(file_download);
  }

  // 下载服务端加密的文件
  {
    std::istringstream iss("put_obj_by_stream_normal_string");
    std::string object_name = "get_sse_object_test";
    PutObjectByStreamReq put_req(m_bucket_name, object_name, iss);
    put_req.SetXCosServerSideEncryption("AES256");
    PutObjectByStreamResp put_resp;
    CosResult put_result = m_client->PutObject(put_req, &put_resp);
    ASSERT_TRUE(put_result.IsSucc());

    std::string file_download = "sse_file_download";
    GetObjectByFileReq get_req(m_bucket_name, object_name, file_download);
    GetObjectByFileResp get_resp;
    CosResult get_result = m_client->GetObject(get_req, &get_resp);
    ASSERT_TRUE(get_result.IsSucc());
    EXPECT_EQ("AES256", get_resp.GetXCosServerSideEncryption());

    std::string file_md5_download = TestUtils::CalcFileMd5(file_download);
    ASSERT_EQ(file_md5_download, get_resp.GetEtag());

    DeleteObjectReq del_req(m_bucket_name, object_name);
    DeleteObjectResp del_resp;
    CosResult del_result = m_client->DeleteObject(del_req, &del_resp);
    ASSERT_TRUE(del_result.IsSucc());

    TestUtils::RemoveFile(file_download);
  }
}

TEST_F(ObjectOpTest, MultiPutObjectTest) {
  {
    uint64_t part_size = 20 * 1000 * 1000;
    uint64_t max_part_num = 3;
    std::string object_name = "object_test_multi";
    InitMultiUploadReq init_req(m_bucket_name, object_name);
    InitMultiUploadResp init_resp;
    CosResult init_result = m_client->InitMultiUpload(init_req, &init_resp);
    ASSERT_TRUE(init_result.IsSucc());

    std::vector<std::string> etags;
    std::vector<uint64_t> part_numbers;
    for (uint64_t part_cnt = 0; part_cnt < max_part_num; ++part_cnt) {
      std::string str(part_size * (part_cnt + 1), 'a');  // 分块大小倍增
      std::stringstream ss;
      ss << str;
      UploadPartDataReq req(m_bucket_name, object_name, init_resp.GetUploadId(),
                            ss);
      UploadPartDataResp resp;
      req.SetPartNumber(part_cnt + 1);
      req.SetRecvTimeoutInms(1000 * 200);

      CosResult result = m_client->UploadPartData(req, &resp);
      ASSERT_TRUE(result.IsSucc());
      etags.push_back(resp.GetEtag());
      part_numbers.push_back(part_cnt + 1);
    }

    // 测试ListParts
    {
      ListPartsReq req(m_bucket_name, object_name, init_resp.GetUploadId());
      ListPartsResp resp;

      CosResult result = m_client->ListParts(req, &resp);
      ASSERT_TRUE(result.IsSucc());
      EXPECT_EQ(m_bucket_name, resp.GetBucket());
      EXPECT_EQ(object_name, resp.GetKey());
      EXPECT_EQ(init_resp.GetUploadId(), resp.GetUploadId());
      const std::vector<Part>& parts = resp.GetParts();
      EXPECT_EQ(max_part_num, parts.size());
      for (size_t idx = 0; idx != parts.size(); ++idx) {
        EXPECT_EQ(part_numbers[idx], parts[idx].m_part_num);
        EXPECT_EQ(part_size * (idx + 1), parts[idx].m_size);
        EXPECT_EQ(etags[idx], parts[idx].m_etag);
      }
    }

    CompleteMultiUploadReq comp_req(m_bucket_name, object_name,
                                    init_resp.GetUploadId());
    CompleteMultiUploadResp comp_resp;
    comp_req.SetEtags(etags);
    comp_req.SetPartNumbers(part_numbers);

    CosResult result = m_client->CompleteMultiUpload(comp_req, &comp_resp);
    EXPECT_TRUE(result.IsSucc());
  }

  // 服务端加密
  {
    uint64_t part_size = 20 * 1000 * 1000;
    uint64_t max_part_num = 3;
    std::string object_name = "object_test_multi_and_enc";
    InitMultiUploadReq init_req(m_bucket_name, object_name);
    init_req.SetXCosServerSideEncryption("AES256");
    InitMultiUploadResp init_resp;
    CosResult init_result = m_client->InitMultiUpload(init_req, &init_resp);
    ASSERT_TRUE(init_result.IsSucc());
    EXPECT_EQ("AES256", init_resp.GetXCosServerSideEncryption());

    std::vector<std::string> etags;
    std::vector<uint64_t> part_numbers;
    for (uint64_t part_cnt = 0; part_cnt < max_part_num; ++part_cnt) {
      std::string str(part_size * (part_cnt + 1), 'b');  // 分块大小倍增
      std::stringstream ss;
      ss << str;
      UploadPartDataReq req(m_bucket_name, object_name, init_resp.GetUploadId(),
                            ss);
      UploadPartDataResp resp;
      req.SetPartNumber(part_cnt + 1);
      req.SetRecvTimeoutInms(1000 * 200);

      CosResult result = m_client->UploadPartData(req, &resp);
      ASSERT_TRUE(result.IsSucc());
      EXPECT_EQ("AES256", resp.GetXCosServerSideEncryption());
      etags.push_back(resp.GetEtag());
      part_numbers.push_back(part_cnt + 1);
    }

    // 测试ListParts
    {
      ListPartsReq req(m_bucket_name, object_name, init_resp.GetUploadId());
      ListPartsResp resp;

      CosResult result = m_client->ListParts(req, &resp);
      ASSERT_TRUE(result.IsSucc());
      EXPECT_EQ(m_bucket_name, resp.GetBucket());
      EXPECT_EQ(object_name, resp.GetKey());
      EXPECT_EQ(init_resp.GetUploadId(), resp.GetUploadId());
      const std::vector<Part>& parts = resp.GetParts();
      EXPECT_EQ(max_part_num, parts.size());
      for (size_t idx = 0; idx != parts.size(); ++idx) {
        EXPECT_EQ(part_numbers[idx], parts[idx].m_part_num);
        EXPECT_EQ(part_size * (idx + 1), parts[idx].m_size);
        EXPECT_EQ(etags[idx], parts[idx].m_etag);
      }
    }

    CompleteMultiUploadReq comp_req(m_bucket_name, object_name,
                                    init_resp.GetUploadId());
    CompleteMultiUploadResp comp_resp;
    comp_req.SetEtags(etags);
    comp_req.SetPartNumbers(part_numbers);

    CosResult result = m_client->CompleteMultiUpload(comp_req, &comp_resp);
    EXPECT_EQ("AES256", comp_resp.GetXCosServerSideEncryption());
    EXPECT_TRUE(result.IsSucc());
  }
}

TEST_F(ObjectOpTest, MultiPutObjectTest_OneStep) {
  {
    std::string filename = "multi_upload_object_one_step";
    std::string object_name = filename;
    // 1. 生成个临时文件, 用于分块上传
    {
      std::ofstream fs;
      fs.open(filename.c_str(), std::ios::out | std::ios::binary);
      std::string str(10 * 1000 * 1000, 'b');
      for (int idx = 0; idx < 10; ++idx) {
        fs << str;
      }
      fs.close();
    }

    // 2. 上传
    MultiPutObjectReq req(m_bucket_name, object_name, filename);
    req.SetRecvTimeoutInms(1000 * 200);
    MultiPutObjectResp resp;

    CosResult result = m_client->MultiPutObject(req, &resp);
    EXPECT_TRUE(result.IsSucc());

    // 3. 删除临时文件
    if (-1 == remove(filename.c_str())) {
      std::cout << "Remove temp file=" << filename << " fail." << std::endl;
    }
  }

  {
    std::string filename = "multi_upload_object_enc_one_step";
    std::string object_name = filename;
    // 1. 生成个临时文件, 用于分块上传
    {
      std::ofstream fs;
      fs.open(filename.c_str(), std::ios::out | std::ios::binary);
      std::string str(10 * 1000 * 1000, 'b');
      for (int idx = 0; idx < 10; ++idx) {
        fs << str;
      }
      fs.close();
    }

    // 2. 上传
    MultiPutObjectReq req(m_bucket_name, object_name, filename);
    req.SetXCosServerSideEncryption("AES256");
    MultiPutObjectResp resp;

    CosResult result = m_client->MultiPutObject(req, &resp);
    ASSERT_TRUE(result.IsSucc());
    EXPECT_EQ("AES256", resp.GetXCosServerSideEncryption());

    // 3. 删除临时文件
    if (-1 == remove(filename.c_str())) {
      std::cout << "Remove temp file=" << filename << " fail." << std::endl;
    }
  }
}

TEST_F(ObjectOpTest, AbortMultiUploadTest) {
  uint64_t part_size = 20 * 1000 * 1000;
  uint64_t max_part_num = 3;
  std::string object_name = "object_test_abort_multi";
  InitMultiUploadReq init_req(m_bucket_name, object_name);
  InitMultiUploadResp init_resp;
  CosResult init_result = m_client->InitMultiUpload(init_req, &init_resp);
  ASSERT_TRUE(init_result.IsSucc());

  std::vector<std::string> etags;
  std::vector<uint64_t> part_numbers;
  for (uint64_t part_cnt = 0; part_cnt < max_part_num; ++part_cnt) {
    std::string str(part_size * (part_cnt + 1), 'a');  // 分块大小倍增
    std::stringstream ss;
    ss << str;
    UploadPartDataReq req(m_bucket_name, object_name, init_resp.GetUploadId(),
                          ss);
    UploadPartDataResp resp;
    req.SetPartNumber(part_cnt + 1);
    req.SetRecvTimeoutInms(1000 * 200);

    CosResult result = m_client->UploadPartData(req, &resp);
    ASSERT_TRUE(result.IsSucc());
    etags.push_back(resp.GetEtag());
    part_numbers.push_back(part_cnt + 1);
  }

  AbortMultiUploadReq abort_req(m_bucket_name, object_name,
                                init_resp.GetUploadId());
  AbortMultiUploadResp abort_resp;

  CosResult result = m_client->AbortMultiUpload(abort_req, &abort_resp);
  ASSERT_TRUE(result.IsSucc());
}

TEST_F(ObjectOpTest, ObjectACLTest) {
  // 1. Put
  {
    std::istringstream iss("put_obj_by_stream_string");
    std::string object_name = "object_test";
    PutObjectByStreamReq put_req(m_bucket_name, object_name, iss);
    PutObjectByStreamResp put_resp;
    CosResult put_result = m_client->PutObject(put_req, &put_resp);
    ASSERT_TRUE(put_result.IsSucc());

    PutObjectACLReq put_acl_req(m_bucket_name, object_name);
    PutObjectACLResp put_acl_resp;
    std::string uin(GetEnvVar("CPP_SDK_V5_UIN"));
    std::string grant_uin(GetEnvVar("CPP_SDK_V5_OTHER_UIN"));

    qcloud_cos::Owner owner = {"qcs::cam::uin/" + uin + ":uin/" + uin,
                               "qcs::cam::uin/" + uin + ":uin/" + uin};
    Grant grant;
    put_acl_req.SetOwner(owner);
    grant.m_perm = "READ";
    grant.m_grantee.m_type = "RootAccount";
    grant.m_grantee.m_uri = "http://cam.qcloud.com/groups/global/AllUsers";
    grant.m_grantee.m_id = "qcs::cam::uin/" + grant_uin + ":uin/" + grant_uin;
    grant.m_grantee.m_display_name =
        "qcs::cam::uin/" + grant_uin + ":uin/" + grant_uin;
    put_acl_req.AddAccessControlList(grant);

    CosResult put_acl_result =
        m_client->PutObjectACL(put_acl_req, &put_acl_resp);
    EXPECT_TRUE(put_acl_result.IsSucc());
  }

  // 2. Get
  {
    // sleep(5);
    GetObjectACLReq req(m_bucket_name, "object_test");
    GetObjectACLResp resp;
    CosResult result = m_client->GetObjectACL(req, &resp);
    EXPECT_TRUE(result.IsSucc());
  }
}

TEST_F(ObjectOpTest, PutObjectCopyTest) {
  std::istringstream iss("put_obj_by_stream_string");
  std::string object_name = "object_test";
  PutObjectByStreamReq req(m_bucket_name, object_name, iss);
  PutObjectByStreamResp resp;
  CosResult result = m_client->PutObject(req, &resp);
  ASSERT_TRUE(result.IsSucc());

  {
    PutObjectCopyReq req(m_bucket_name2, "object_test_copy_from_bucket1");
    PutObjectCopyResp resp;
    std::string source = m_bucket_name + "." + m_config->GetRegion() +
                         ".mycloud.com/" + object_name;
    req.SetXCosCopySource(source);

    CosResult result = m_client->PutObjectCopy(req, &resp);
    EXPECT_TRUE(result.IsSucc());
  }

  {
    PutObjectCopyReq req(m_bucket_name2, "object_enc_test_copy_from_bucket1");
    PutObjectCopyResp resp;
    std::string source = m_bucket_name + "." + m_config->GetRegion() +
                         ".mycloud.com/" + object_name;
    req.SetXCosCopySource(source);
    req.SetXCosServerSideEncryption("AES256");

    CosResult result = m_client->PutObjectCopy(req, &resp);
    EXPECT_TRUE(result.IsSucc());
    EXPECT_EQ("AES256", resp.GetXCosServerSideEncryption());
  }
}

TEST_F(ObjectOpTest, GeneratePresignedUrlTest) {
  bool use_dns_cache = CosSysConfig::GetUseDnsCache();
  CosSysConfig::SetUseDnsCache(false);
  {
    GeneratePresignedUrlReq req(m_bucket_name, "object_test", HTTP_GET);
    req.SetStartTimeInSec(0);
    req.SetExpiredTimeInSec(5 * 60);

    std::string presigned_url = m_client->GeneratePresignedUrl(req);
    EXPECT_FALSE(presigned_url.empty());
    EXPECT_TRUE(StringUtil::StringStartsWith(presigned_url, "https"));

    // TODO(sevenyou) 先直接调 curl 命令看下是否正常
    std::string curl_url = "curl " + presigned_url;
    int ret = system(curl_url.c_str());
    EXPECT_EQ(0, ret);
  }

  {
    std::string presigned_url =
        m_client->GeneratePresignedUrl(m_bucket_name, "object_test", 0, 0);
    // TODO(sevenyou) 先直接调 curl 命令看下是否正常
    std::string curl_url = "curl " + presigned_url;
    int ret = system(curl_url.c_str());
    EXPECT_EQ(0, ret);
  }

  {
    GeneratePresignedUrlReq req(m_bucket_name, "object_test", HTTP_GET);
    req.SetUseHttps(false);
    std::string presigned_url = m_client->GeneratePresignedUrl(req);
    EXPECT_TRUE(StringUtil::StringStartsWith(presigned_url, "http"));
    EXPECT_TRUE(presigned_url.find("host") != std::string::npos);
  }

  {
    GeneratePresignedUrlReq req(m_bucket_name, "object_test", HTTP_GET);
    req.SetSignHeaderHost(false);
    std::string presigned_url = m_client->GeneratePresignedUrl(req);
    EXPECT_TRUE(StringUtil::StringStartsWith(presigned_url, "https"));
    EXPECT_TRUE(presigned_url.find("host") == std::string::npos);
  }
  CosSysConfig::SetUseDnsCache(use_dns_cache);
}

TEST_F(ObjectOpTest, PutObjectWithMultiMeta) {
  // put object
  {
    std::istringstream iss("put_obj_by_stream_normal_string");
    PutObjectByStreamReq req(m_bucket_name, "object_test_with_multiheader",
                             iss);
    req.SetContentDisposition("attachment; filename=example");
    req.SetContentType("image/jpeg");
    req.SetContentEncoding("compress");
    req.SetXCosMeta("key1", "val1");
    req.SetXCosMeta("key2", "val2");
    PutObjectByStreamResp resp;
    CosResult result = m_client->PutObject(req, &resp);
    ASSERT_TRUE(result.IsSucc());
  }
  // head object
  {
    HeadObjectReq req(m_bucket_name, "object_test_with_multiheader");
    HeadObjectResp resp;
    CosResult result = m_client->HeadObject(req, &resp);
    ASSERT_TRUE(result.IsSucc());
    EXPECT_EQ("image/jpeg", resp.GetContentType());
    EXPECT_EQ("attachment; filename=example", resp.GetContentDisposition());
    EXPECT_EQ("compress", resp.GetContentEncoding());
    EXPECT_EQ(resp.GetXCosMeta("key1"), "val1");
    EXPECT_EQ(resp.GetXCosMeta("key2"), "val2");
  }
}

TEST_F(ObjectOpTest, ObjectOptionsDefault) {
  // put object
  {
    std::istringstream iss("test string");
    PutObjectByStreamReq req(m_bucket_name, "object_test_origin", iss);
    PutObjectByStreamResp resp;
    CosResult result = m_client->PutObject(req, &resp);
    ASSERT_TRUE(result.IsSucc());
  }
  // test default option
  {
    OptionsObjectReq req(m_bucket_name, "object_test_origin");
    req.SetOrigin("https://console.cloud.tencent.com");
    req.SetAccessControlRequestMethod("GET");
    req.SetAccessControlRequestHeaders("Content-Length");
    OptionsObjectResp resp;
    CosResult result = m_client->OptionsObject(req, &resp);
    EXPECT_EQ(resp.GetAccessControAllowOrigin(),
              "https://console.cloud.tencent.com");
    EXPECT_EQ(resp.GetAccessControlAllowMethods(), "GET,PUT,POST,HEAD,DELETE");
    EXPECT_EQ(resp.GetAccessControlAllowHeaders(), "Content-Length");
    ASSERT_TRUE(result.IsSucc());
  }

  // put bucket cors and option object
  {
    PutBucketCORSReq req(m_bucket_name);
    PutBucketCORSResp resp;
    CORSRule rule;
    rule.m_id = "cors_rule_00";
    rule.m_max_age_secs = "600";
    rule.m_allowed_headers.push_back("x-cos-header-test1");
    rule.m_allowed_headers.push_back("x-cos-header-test2");
    rule.m_allowed_origins.push_back("http://www.123.com");
    rule.m_allowed_origins.push_back("http://www.abc.com");
    rule.m_allowed_methods.push_back("PUT");
    rule.m_allowed_methods.push_back("GET");
    rule.m_expose_headers.push_back("x-cos-expose-headers");
    req.AddRule(rule);
    CosResult result = m_client->PutBucketCORS(req, &resp);
    ASSERT_TRUE(result.IsSucc());
  }

  // options object allow
  {
    OptionsObjectReq req(m_bucket_name, "object_test_origin");
    req.SetOrigin("http://www.123.com");
    req.SetAccessControlRequestMethod("GET");
    req.SetAccessControlRequestHeaders("x-cos-header-test1");
    OptionsObjectResp resp;
    CosResult result = m_client->OptionsObject(req, &resp);
    EXPECT_EQ(resp.GetAccessControAllowOrigin(), "http://www.123.com");
    EXPECT_EQ(resp.GetAccessControlAllowMethods(), "PUT,GET");
    EXPECT_EQ(resp.GetAccessControlAllowHeaders(),
              "x-cos-header-test1,x-cos-header-test2");
    EXPECT_EQ(resp.GetAccessControlExposeHeaders(), "x-cos-expose-headers");
    EXPECT_EQ(resp.GetAccessControlMaxAge(), "600");
    ASSERT_TRUE(result.IsSucc());
  }
  // options object allow
  {
    OptionsObjectReq req(m_bucket_name, "object_test_origin");
    req.SetOrigin("http://www.abc.com");
    req.SetAccessControlRequestMethod("PUT");
    req.SetAccessControlRequestHeaders("x-cos-header-test2");
    OptionsObjectResp resp;
    CosResult result = m_client->OptionsObject(req, &resp);
    EXPECT_EQ(resp.GetAccessControAllowOrigin(), "http://www.abc.com");
    EXPECT_EQ(resp.GetAccessControlAllowMethods(), "PUT,GET");
    EXPECT_EQ(resp.GetAccessControlAllowHeaders(),
              "x-cos-header-test1,x-cos-header-test2");
    EXPECT_EQ(resp.GetAccessControlExposeHeaders(), "x-cos-expose-headers");
    EXPECT_EQ(resp.GetAccessControlMaxAge(), "600");
    ASSERT_TRUE(result.IsSucc());
  }

  // options object not allow
  {
    OptionsObjectReq req(m_bucket_name, "object_test_origin");
    req.SetOrigin("http://www.1234.com");
    req.SetAccessControlRequestMethod("GET");
    req.SetAccessControlRequestHeaders("x-cos-header-test");
    OptionsObjectResp resp;
    CosResult result = m_client->OptionsObject(req, &resp);
    EXPECT_EQ(resp.GetAccessControAllowOrigin(), "");
    EXPECT_EQ(resp.GetAccessControlAllowMethods(), "");
    EXPECT_EQ(resp.GetAccessControlAllowHeaders(), "");
    EXPECT_EQ(resp.GetAccessControlExposeHeaders(), "");
    EXPECT_EQ(resp.GetAccessControlMaxAge(), "");
    ASSERT_TRUE(!result.IsSucc());
    EXPECT_EQ(result.GetHttpStatus(), 403);
  }
}

TEST_F(ObjectOpTest, SelectObjectContent) {
  std::string input_str;
  // put json object
  {
    std::istringstream iss("{\"aaa\":111,\"bbb\":222,\"ccc\":\"333\"}");
    input_str = iss.str();
    PutObjectByStreamReq req(m_bucket_name, "testjson", iss);
    PutObjectByStreamResp resp;
    CosResult result = m_client->PutObject(req, &resp);
    ASSERT_TRUE(result.IsSucc());
  }
  // select object content, input json, output json
  {
    SelectObjectContentReq req(m_bucket_name, "testjson", JSON, COMPRESS_NONE,
                               JSON);
    SelectObjectContentResp resp;
    req.SetSqlExpression("Select * from COSObject");
    CosResult result = m_client->SelectObjectContent(req, &resp);
    ASSERT_TRUE(result.IsSucc());
    resp.PrintResult();
    EXPECT_EQ(0, resp.WriteResultToLocalFile("select_result.json"));
    std::ifstream ifs("select_result.json");
    std::stringstream strstream;
    // read the file
    strstream << ifs.rdbuf();
    // compare
    EXPECT_EQ(0, input_str.compare(StringUtil::Trim(strstream.str(), "\\n")));
    EXPECT_EQ(0, ::remove("select_result.json"));
  }
  // select object content using filter, input json, output json,
  {
    SelectObjectContentReq req(m_bucket_name, "testjson", JSON, COMPRESS_NONE,
                               JSON);
    SelectObjectContentResp resp;
    req.SetSqlExpression("Select testjson.aaa from COSObject testjson");
    CosResult result = m_client->SelectObjectContent(req, &resp);
    ASSERT_TRUE(result.IsSucc());
    resp.PrintResult();
    EXPECT_EQ(0, resp.WriteResultToLocalFile("select_result.json"));
    std::ifstream ifs("select_result.json");
    std::stringstream strstream;
    strstream << ifs.rdbuf();
    // compare
    EXPECT_EQ(
        0, StringUtil::Trim(strstream.str(), "\\n").compare("{\"aaa\":111}"));
    EXPECT_EQ(0, ::remove("select_result.json"));
  }

  // select object content using filter, input json, output json,
  {
    SelectObjectContentReq req(m_bucket_name, "testjson", JSON, COMPRESS_NONE,
                               CSV);
    SelectObjectContentResp resp;
    req.SetSqlExpression("Select * from COSObject testjson");
    CosResult result = m_client->SelectObjectContent(req, &resp);
    ASSERT_TRUE(result.IsSucc());
    resp.PrintResult();
    EXPECT_EQ(0, resp.WriteResultToLocalFile("select_result.csv"));
    // std::ifstream ifs("select_result.csv");
    // std::stringstream strstream;
    // strstream << ifs.rdbuf();
    // compare
    // EXPECT_EQ(0, StringUtil::Trim(strstream.str(),
    // "\\n").compare("{\"aaa\":111}"));
    EXPECT_EQ(0, ::remove("select_result.csv"));
  }
  // put csv object
  {
    std::istringstream iss("aaa,111,bbb,222,ccc,333");
    input_str = iss.str();
    PutObjectByStreamReq req(m_bucket_name, "testcsv", iss);
    PutObjectByStreamResp resp;
    CosResult result = m_client->PutObject(req, &resp);
    ASSERT_TRUE(result.IsSucc());
  }
  // select object content, input csv, output csv
  {
    SelectObjectContentReq req(m_bucket_name, "testcsv", CSV, COMPRESS_NONE,
                               CSV);
    SelectObjectContentResp resp;
    req.SetSqlExpression("Select * from COSObject");
    CosResult result = m_client->SelectObjectContent(req, &resp);
    ASSERT_TRUE(result.IsSucc());
    resp.PrintResult();
    EXPECT_EQ(0, resp.WriteResultToLocalFile("select_result.csv"));
    std::ifstream ifs("select_result.csv");
    std::stringstream strstream;
    strstream << ifs.rdbuf();
    // compare
    EXPECT_EQ(0, input_str.compare(StringUtil::Trim(strstream.str(), "\\\\n")));
    EXPECT_EQ(0, ::remove("select_result.csv"));
  }
}

TEST_F(ObjectOpTest, TestPutObjectWithMeta) {
  std::vector<int> base_size_v = {1024};
  for (auto& size : base_size_v) {
    for (int i = 0; i < 5; i++) {
      std::cout << "base_size: " << size << ", test_time: " << i << std::endl;
      size_t file_size = ((rand() % 100) + 1) * size;
      std::string object_name =
          "test_putobjectwithmeta_" + std::to_string(file_size);
      std::string local_file = "./" + object_name;

      std::cout << "generate file: " << local_file << std::endl;
      TestUtils::WriteRandomDatatoFile(local_file, file_size);

      // put object
      qcloud_cos::PutObjectByFileReq put_req(m_bucket_name, object_name,
                                             local_file);
      put_req.SetXCosStorageClass(kStorageClassStandardIA);
      put_req.SetCacheControl("max-age=86400");
      put_req.SetXCosMeta("key1", "val1");
      put_req.SetXCosMeta("key2", "val2");
      put_req.SetXCosAcl(kAclPublicRead);
      put_req.SetExpires("1000");
      put_req.SetContentEncoding("gzip");
      put_req.SetContentDisposition("attachment; filename=example");
      put_req.SetContentType("image/jpeg");
      qcloud_cos::PutObjectByFileResp put_resp;
      std::cout << "upload object: " << object_name << ", size: " << file_size
                << std::endl;
      CosResult put_result = m_client->PutObject(put_req, &put_resp);
      ASSERT_TRUE(put_result.IsSucc());
      ASSERT_TRUE(!put_resp.GetXCosRequestId().empty());
      ASSERT_TRUE(put_resp.GetContentLength() == 0);
      ASSERT_TRUE(!put_resp.GetConnection().empty());
      ASSERT_TRUE(!put_resp.GetDate().empty());
      ASSERT_EQ(put_resp.GetServer(), "tencent-cos");

      // check crc64 and md5
      uint64_t file_crc64_origin = FileUtil::GetFileCrc64(local_file);
      ASSERT_EQ(put_resp.GetXCosHashCrc64Ecma(),
                std::to_string(file_crc64_origin));
      std::string file_md5_origin = FileUtil::GetFileMd5(local_file);
      ASSERT_EQ(put_resp.GetEtag(), file_md5_origin);

      // head object
      std::cout << "head object: " << object_name << std::endl;
      HeadObjectReq head_req(m_bucket_name, object_name);
      HeadObjectResp head_resp;
      CosResult head_result = m_client->HeadObject(head_req, &head_resp);

      // check common headers
      ASSERT_TRUE(head_result.IsSucc());
      ASSERT_TRUE(!head_resp.GetXCosRequestId().empty());
      ASSERT_TRUE(!head_resp.GetConnection().empty());
      ASSERT_TRUE(!head_resp.GetDate().empty());
      ASSERT_EQ(head_resp.GetServer(), "tencent-cos");
      // checkout crcr64 and md5
      ASSERT_EQ(head_resp.GetXCosHashCrc64Ecma(),
                std::to_string(file_crc64_origin));
      ASSERT_EQ(head_resp.GetEtag(), file_md5_origin);

      // check meta
      ASSERT_EQ(head_resp.GetXCosMeta("key1"), "val1");
      ASSERT_EQ(head_resp.GetXCosMeta("key2"), "val2");
      ASSERT_EQ(head_resp.GetXCosStorageClass(), kStorageClassStandardIA);
      ASSERT_EQ(head_resp.GetExpires(), "1000");
      ASSERT_EQ(head_resp.GetContentLength(), file_size);
      ASSERT_EQ(head_resp.GetContentEncoding(), "gzip");
      ASSERT_EQ(head_resp.GetContentDisposition(),
                "attachment; filename=example");
      ASSERT_EQ(head_resp.GetContentType(), "image/jpeg");

      // TODO check acl
      // TODO check if-modified-since

      // get object
      std::string local_file_download = local_file + "_download";
      std::cout << "get object: " << object_name << std::endl;
      qcloud_cos::GetObjectByFileReq get_req(m_bucket_name, object_name,
                                             local_file_download);
      qcloud_cos::GetObjectByFileResp get_resp;
      CosResult get_result = m_client->GetObject(get_req, &get_resp);
      // checkout common header
      ASSERT_TRUE(get_result.IsSucc());
      ASSERT_TRUE(!get_resp.GetXCosRequestId().empty());
      ASSERT_TRUE(!get_resp.GetConnection().empty());
      ASSERT_TRUE(!get_resp.GetDate().empty());
      ASSERT_EQ(get_resp.GetServer(), "tencent-cos");

      // checkout crcr64 and md5
      ASSERT_EQ(get_resp.GetXCosHashCrc64Ecma(),
                std::to_string(file_crc64_origin));
      ASSERT_EQ(get_resp.GetEtag(), file_md5_origin);
      std::string file_md5_download =
          TestUtils::CalcFileMd5(local_file_download);
      ASSERT_EQ(file_md5_origin, file_md5_download);
      uint64_t file_crc64_download =
          FileUtil::GetFileCrc64(local_file_download);
      ASSERT_EQ(file_crc64_origin, file_crc64_download);

      // check meta
      ASSERT_EQ(get_resp.GetXCosMeta("key1"), "val1");
      ASSERT_EQ(get_resp.GetXCosMeta("key2"), "val2");
      ASSERT_EQ(get_resp.GetXCosStorageClass(), kStorageClassStandardIA);
      ASSERT_EQ(get_resp.GetExpires(), "1000");
      ASSERT_EQ(get_resp.GetContentLength(), file_size);
      ASSERT_EQ(get_resp.GetContentEncoding(), "gzip");
      ASSERT_EQ(get_resp.GetContentDisposition(),
                "attachment; filename=example");
      ASSERT_EQ(get_resp.GetContentType(), "image/jpeg");

      // delete object
      std::cout << "delete object: " << object_name << std::endl;
      qcloud_cos::DeleteObjectReq del_req(m_bucket_name, object_name);
      qcloud_cos::DeleteObjectResp del_resp;
      CosResult del_result = m_client->DeleteObject(del_req, &del_resp);
      // checkout common header
      ASSERT_TRUE(del_result.IsSucc());
      ASSERT_TRUE(!del_resp.GetXCosRequestId().empty());
      ASSERT_TRUE(!del_resp.GetConnection().empty());
      ASSERT_TRUE(!del_resp.GetDate().empty());
      ASSERT_EQ(del_resp.GetServer(), "tencent-cos");

      // remote local file
      TestUtils::RemoveFile(local_file);
      TestUtils::RemoveFile(local_file_download);
    }
  }
}

TEST_F(ObjectOpTest, TestMultiPutObjectWithMeta) {
  std::vector<int> base_size_v = {1024 * 1024};
  for (auto& size : base_size_v) {
    for (int i = 0; i < 5; i++) {
      std::cout << "base_size: " << size << ", test_time: " << i << std::endl;
      size_t file_size = ((rand() % 100) + 1) * size;
      std::string object_name =
          "test_putobjectwithmeta_" + std::to_string(file_size);
      std::string local_file = "./" + object_name;

      std::cout << "generate file: " << local_file << std::endl;
      TestUtils::WriteRandomDatatoFile(local_file, file_size);

      // put object
      qcloud_cos::MultiPutObjectReq put_req(m_bucket_name, object_name,
                                            local_file);
      put_req.SetXCosStorageClass(kStorageClassStandardIA);
      put_req.SetCacheControl("max-age=86400");
      put_req.SetXCosMeta("key1", "val1");
      put_req.SetXCosMeta("key2", "val2");
      put_req.SetXCosAcl(kAclPublicRead);
      put_req.SetExpires("1000");
      put_req.SetContentEncoding("gzip");
      put_req.SetContentDisposition("attachment; filename=example");
      put_req.SetContentType("image/jpeg");
      qcloud_cos::MultiPutObjectResp put_resp;
      std::cout << "upload object: " << object_name << ", size: " << file_size
                << std::endl;
      CosResult put_result = m_client->MultiPutObject(put_req, &put_resp);
      ASSERT_TRUE(put_result.IsSucc());
      ASSERT_TRUE(!put_resp.GetXCosRequestId().empty());
      ASSERT_EQ(put_resp.GetContentLength(), 0);
      ASSERT_TRUE(!put_resp.GetConnection().empty());
      ASSERT_TRUE(!put_resp.GetDate().empty());
      ASSERT_EQ(put_resp.GetServer(), "tencent-cos");

      // check crc64 and md5
      uint64_t file_crc64_origin = FileUtil::GetFileCrc64(local_file);
      ASSERT_EQ(put_resp.GetXCosHashCrc64Ecma(),
                std::to_string(file_crc64_origin));
      std::string file_md5_origin = FileUtil::GetFileMd5(local_file);
      // multipart upload etag not equal to md5
      ASSERT_NE(put_resp.GetEtag(), file_md5_origin);

      // head object
      std::cout << "head object: " << object_name << std::endl;
      HeadObjectReq head_req(m_bucket_name, object_name);
      HeadObjectResp head_resp;
      CosResult head_result = m_client->HeadObject(head_req, &head_resp);

      // check common headers
      ASSERT_TRUE(head_result.IsSucc());
      ASSERT_TRUE(!head_resp.GetXCosRequestId().empty());
      ASSERT_TRUE(!head_resp.GetConnection().empty());
      ASSERT_TRUE(!head_resp.GetDate().empty());
      ASSERT_EQ(head_resp.GetServer(), "tencent-cos");
      // checkout crcr64 and md5
      ASSERT_EQ(head_resp.GetXCosHashCrc64Ecma(),
                std::to_string(file_crc64_origin));
      // multipart upload etag not equal to md5
      ASSERT_NE(head_resp.GetEtag(), file_md5_origin);

      // check meta
      ASSERT_EQ(head_resp.GetXCosMeta("key1"), "val1");
      ASSERT_EQ(head_resp.GetXCosMeta("key2"), "val2");
      ASSERT_EQ(head_resp.GetXCosStorageClass(), kStorageClassStandardIA);
      ASSERT_EQ(head_resp.GetExpires(), "1000");
      ASSERT_EQ(head_resp.GetContentLength(), file_size);
      ASSERT_EQ(head_resp.GetContentEncoding(), "gzip");
      ASSERT_EQ(head_resp.GetContentDisposition(),
                "attachment; filename=example");
      ASSERT_EQ(head_resp.GetContentType(), "image/jpeg");

      // TODO check acl
      // TODO check if-modified-since

      // get object
      std::string local_file_download = local_file + "_download";
      std::cout << "get object: " << object_name << std::endl;
      qcloud_cos::MultiGetObjectReq get_req(m_bucket_name, object_name,
                                            local_file_download);
      qcloud_cos::MultiGetObjectResp get_resp;
      CosResult get_result = m_client->MultiGetObject(get_req, &get_resp);
      // checkout common header
      ASSERT_TRUE(get_result.IsSucc());
      ASSERT_TRUE(!get_resp.GetXCosRequestId().empty());
      ASSERT_TRUE(!get_resp.GetConnection().empty());
      ASSERT_TRUE(!get_resp.GetDate().empty());
      ASSERT_EQ(get_resp.GetServer(), "tencent-cos");

      // checkout crcr64 and md5
      ASSERT_EQ(get_resp.GetXCosHashCrc64Ecma(),
                std::to_string(file_crc64_origin));
      ASSERT_NE(get_resp.GetEtag(), file_md5_origin);
      std::string file_md5_download =
          TestUtils::CalcFileMd5(local_file_download);
      ASSERT_EQ(file_md5_origin, file_md5_download);
      uint64_t file_crc64_download =
          FileUtil::GetFileCrc64(local_file_download);
      ASSERT_EQ(file_crc64_origin, file_crc64_download);

      // check meta
      ASSERT_EQ(get_resp.GetXCosMeta("key1"), "val1");
      ASSERT_EQ(get_resp.GetXCosMeta("key2"), "val2");
      ASSERT_EQ(get_resp.GetXCosStorageClass(), kStorageClassStandardIA);
      ASSERT_EQ(get_resp.GetExpires(), "1000");
      //ASSERT_EQ(get_resp.GetContentLength(), file_size);
      ASSERT_EQ(get_resp.GetContentEncoding(), "gzip");
      ASSERT_EQ(get_resp.GetContentDisposition(),
                "attachment; filename=example");
      ASSERT_EQ(get_resp.GetContentType(), "image/jpeg");

      // delete object
      std::cout << "delete object: " << object_name << std::endl;
      qcloud_cos::DeleteObjectReq del_req(m_bucket_name, object_name);
      qcloud_cos::DeleteObjectResp del_resp;
      CosResult del_result = m_client->DeleteObject(del_req, &del_resp);
      // checkout common header
      ASSERT_TRUE(del_result.IsSucc());
      ASSERT_TRUE(!del_resp.GetXCosRequestId().empty());
      ASSERT_TRUE(!del_resp.GetConnection().empty());
      ASSERT_TRUE(!del_resp.GetDate().empty());
      ASSERT_EQ(del_resp.GetServer(), "tencent-cos");

      // remove local file
      TestUtils::RemoveFile(local_file);
      TestUtils::RemoveFile(local_file_download);
    }
  }
}

TEST_F(ObjectOpTest, AppendObjectTest) {
  const int append_times = 100;
  int append_position = 0;
  int total_object_len = 0;
  std::string object_name = "test_append_object";
  for (int i = 0; i < append_times; i++) {
    int random_str_len = (rand() % 1024) + 1;
    std::cout << "append size: " << random_str_len << std::endl;
    total_object_len += random_str_len;
    std::string test_str = TestUtils::GetRandomString(random_str_len);
    std::istringstream iss(test_str);
    AppendObjectReq append_req(m_bucket_name, object_name, iss);
    append_req.SetPosition(std::to_string(append_position));
    AppendObjectResp append_resp;
    CosResult append_result = m_client->AppendObject(append_req, &append_resp);
    ASSERT_TRUE(append_result.IsSucc());
    ASSERT_TRUE(!append_resp.GetXCosRequestId().empty());
    ASSERT_EQ(append_resp.GetContentLength(), 0);
    ASSERT_TRUE(!append_resp.GetConnection().empty());
    ASSERT_TRUE(!append_resp.GetDate().empty());
    ASSERT_EQ(append_resp.GetServer(), "tencent-cos");
    ASSERT_EQ(append_resp.GetNextPosition(), std::to_string(total_object_len));

    // check md5
    ASSERT_EQ(append_resp.GetXCosContentSha1(),
              TestUtils::CalcStringMd5(test_str));

    // append again with old position, reuturn 409
    std::istringstream err_iss(test_str);
    AppendObjectReq err_append_req(m_bucket_name, object_name, err_iss);
    AppendObjectResp err_append_resp;
    CosResult err_append_result =
        m_client->AppendObject(err_append_req, &err_append_resp);
    ASSERT_TRUE(!err_append_result.IsSucc());
    ASSERT_EQ(err_append_result.GetHttpStatus(), 409);

    // head object
    HeadObjectReq head_req(m_bucket_name, object_name);
    HeadObjectResp head_resp;
    CosResult head_result = m_client->HeadObject(head_req, &head_resp);
    ASSERT_TRUE(head_result.IsSucc());
    ASSERT_TRUE(!head_resp.GetXCosRequestId().empty());
    ASSERT_EQ(head_resp.GetContentLength(), total_object_len);
    ASSERT_TRUE(!append_resp.GetConnection().empty());
    ASSERT_TRUE(!append_resp.GetDate().empty());
    ASSERT_EQ(head_resp.GetServer(), "tencent-cos");
    // ASSERT_EQ(head_resp.GetEtag(), TestUtils::CalcStreamMd5(iss));
    ASSERT_EQ(head_resp.GetXCosObjectType(), kObjectTypeAppendable);

    // update position
    append_position = total_object_len;
  }

  // delete object
  DeleteObjectReq delete_req(m_bucket_name, object_name);
  DeleteObjectResp delete_resp;
  CosResult delete_result = m_client->DeleteObject(delete_req, &delete_resp);
  ASSERT_TRUE(delete_result.IsSucc());
  ASSERT_TRUE(!delete_resp.GetXCosRequestId().empty());
  ASSERT_EQ(delete_resp.GetContentLength(), 0);
  ASSERT_TRUE(!delete_resp.GetConnection().empty());
  ASSERT_TRUE(!delete_resp.GetDate().empty());
  ASSERT_EQ(delete_resp.GetServer(), "tencent-cos");
}

TEST_F(ObjectOpTest, UriTest) {
  BaseOp base_op;
  std::string host = "cos.ap-guangzhou.myqcloud.com";
  std::string path = "/a/b/c";
  CosSysConfig::SetUseDnsCache(false);
  ASSERT_EQ(base_op.GetRealUrl(host, path, false),
            "http://cos.ap-guangzhou.myqcloud.com/a/b/c");
  ASSERT_EQ(base_op.GetRealUrl(host, path, true),
            "https://cos.ap-guangzhou.myqcloud.com/a/b/c");
  // set private ip
  CosSysConfig::SetIsUseIntranet(true);
  CosSysConfig::SetIntranetAddr("1.1.1.1");
  ASSERT_EQ(base_op.GetRealUrl(host, path, false), "http://1.1.1.1/a/b/c");

  // set domain
  CosSysConfig::SetDestDomain("mydomain.com");
  ASSERT_EQ(base_op.GetRealUrl(host, path, false), "http://1.1.1.1/a/b/c");
  CosSysConfig::SetIsUseIntranet(false);
  ASSERT_EQ(base_op.GetRealUrl(host, path, false), "http://mydomain.com/a/b/c");

  // set dns cache
  CosSysConfig::SetIsUseIntranet(false);
  CosSysConfig::SetDestDomain("");
  CosSysConfig::SetUseDnsCache(true);
  for (auto i = 0; i < 10000; ++i) {
    ASSERT_NE(base_op.GetRealUrl(host, path, false), "http:///a/b/c");
  }
  CosSysConfig::SetUseDnsCache(false);
}

TEST_F(ObjectOpTest, DnsCachePerfTest) {
  const int test_times = 100;
  unsigned cosume_ms = 0;
  CosSysConfig::SetUseDnsCache(false);
  std::chrono::time_point<std::chrono::steady_clock> start_ts, end_ts;
  start_ts = std::chrono::steady_clock::now();
  for (int i = 0; i < test_times; i++) {
    std::istringstream iss("put_obj_by_stream_normal_string");
    PutObjectByStreamReq put_req(m_bucket_name, "test_put_without_dns_cache",
                                 iss);
    PutObjectByStreamResp put_resp;
    CosResult result = m_client->PutObject(put_req, &put_resp);
    ASSERT_TRUE(result.IsSucc());
  }

  end_ts = std::chrono::steady_clock::now();
  cosume_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(end_ts - start_ts)
          .count();
  std::cout << "put object without dns cache, comsume: " << cosume_ms
            << std::endl;

  CosSysConfig::SetUseDnsCache(true);
  start_ts = std::chrono::steady_clock::now();
  for (int i = 0; i < test_times; i++) {
    std::istringstream iss("put_obj_by_stream_normal_string");
    PutObjectByStreamReq put_req(m_bucket_name, "test_put_with_dns_cache", iss);
    PutObjectByStreamResp put_resp;
    CosResult result = m_client->PutObject(put_req, &put_resp);
    ASSERT_TRUE(result.IsSucc());
  }
  end_ts = std::chrono::steady_clock::now();

  cosume_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(end_ts - start_ts)
          .count();
  std::cout << "put object with dns cache, comsume: " << cosume_ms << std::endl;
  CosSysConfig::SetUseDnsCache(false);
}

TEST_F(ObjectOpTest, MultiUploadVaryName) {
  std::vector<std::string> object_name_list = {"test_multiupload_object",
                                               "测试上传中文", "测试上传韩文",
                                               "のテストアップロード"};
  size_t test_file_size = 100 * 1024 * 1024;
  for (auto& object_name : object_name_list) {
    std::cout << "test object_name: " << object_name << std::endl;
    std::string local_file = "./" + object_name;
    std::cout << "generate file: " << local_file << std::endl;
    TestUtils::WriteRandomDatatoFile(local_file, test_file_size);
    uint64_t file_crc64_origin = FileUtil::GetFileCrc64(local_file);
    MultiPutObjectReq multiupload_req(m_bucket_name, object_name, local_file);
    MultiPutObjectResp multiupload_resp;
    ASSERT_TRUE(multiupload_req.CheckCRC64());

    // upload object
    CosResult multiupload_result =
        m_client->MultiPutObject(multiupload_req, &multiupload_resp);
    ASSERT_TRUE(multiupload_result.IsSucc());
    ASSERT_TRUE(!multiupload_resp.GetXCosRequestId().empty());
    ASSERT_TRUE(multiupload_resp.GetContentLength() == 0);
    ASSERT_TRUE(!multiupload_resp.GetConnection().empty());
    ASSERT_TRUE(!multiupload_resp.GetDate().empty());
    ASSERT_EQ(multiupload_resp.GetServer(), "tencent-cos");
    ASSERT_EQ(multiupload_resp.GetXCosHashCrc64Ecma(),
              std::to_string(file_crc64_origin));

    // head object
    std::cout << "head object: " << object_name << std::endl;
    HeadObjectReq head_req(m_bucket_name, object_name);
    HeadObjectResp head_resp;
    CosResult head_result = m_client->HeadObject(head_req, &head_resp);
    ASSERT_TRUE(head_result.IsSucc());
    ASSERT_TRUE(!head_result.GetXCosRequestId().empty());
    ASSERT_EQ(head_resp.GetContentLength(), test_file_size);
    ASSERT_TRUE(!head_resp.GetDate().empty());
    ASSERT_EQ(head_resp.GetServer(), "tencent-cos");
    ASSERT_EQ(head_resp.GetXCosHashCrc64Ecma(),
              std::to_string(file_crc64_origin));

    // delete object
    std::cout << "delete object: " << object_name << std::endl;
    qcloud_cos::DeleteObjectReq del_req(m_bucket_name, object_name);
    qcloud_cos::DeleteObjectResp del_resp;
    CosResult del_result = m_client->DeleteObject(del_req, &del_resp);
    // checkout common header
    ASSERT_TRUE(del_result.IsSucc());
    ASSERT_TRUE(!del_resp.GetXCosRequestId().empty());
    ASSERT_TRUE(!del_resp.GetConnection().empty());
    ASSERT_TRUE(!del_resp.GetDate().empty());
    ASSERT_EQ(del_resp.GetServer(), "tencent-cos");

    // remove local file
    TestUtils::RemoveFile(local_file);
  }

  {
    // upload not exist file
    std::string object_name = "not_exist_file";
    std::string local_file_not_exist = "./not_exist_file";
    MultiPutObjectReq multiupload_req(m_bucket_name, object_name,
                                      local_file_not_exist);
    MultiPutObjectResp multiupload_resp;
    CosResult result = m_client->MultiPutObject(multiupload_req, &multiupload_resp);
    ASSERT_TRUE(!result.IsSucc());
    ASSERT_TRUE(result.GetErrorMsg().find("Failed to open file") !=
                std::string::npos);
  }
}

TEST_F(ObjectOpTest, MultiUploadVaryPartSizeAndThreadPoolSize) {
  std::vector<unsigned> part_size_list = {1024 * 1024, 1024 * 1024 * 4,
                                          1024 * 1024 * 10, 1024 * 1024 * 20};
  std::vector<unsigned> thread_pool_size_list = {1, 4, 10, 16};
  size_t test_file_size = 100 * 1024 * 1024;
  for (auto& part_size : part_size_list) {
    for (auto& thead_pool_size : thread_pool_size_list) {
      std::cout << "part_size : " << part_size
                << ", thead_pool_size: " << thead_pool_size << std::endl;
      CosSysConfig::SetUploadPartSize(part_size);
      CosSysConfig::SetUploadThreadPoolSize(thead_pool_size);
      std::string object_name = "test_multiupload_object";
      std::string local_file = "./" + object_name;
      std::cout << "generate file: " << local_file << std::endl;
      TestUtils::WriteRandomDatatoFile(local_file, test_file_size);
      uint64_t file_crc64_origin = FileUtil::GetFileCrc64(local_file);
      MultiPutObjectReq multiupload_req(m_bucket_name, object_name, local_file);
      MultiPutObjectResp multiupload_resp;
      ASSERT_TRUE(multiupload_req.CheckCRC64());

      // upload object
      CosResult multiupload_result =
          m_client->MultiPutObject(multiupload_req, &multiupload_resp);
      ASSERT_TRUE(multiupload_result.IsSucc());
      ASSERT_TRUE(!multiupload_resp.GetXCosRequestId().empty());
      ASSERT_TRUE(multiupload_resp.GetContentLength() == 0);
      ASSERT_TRUE(!multiupload_resp.GetConnection().empty());
      ASSERT_TRUE(!multiupload_resp.GetDate().empty());
      ASSERT_EQ(multiupload_resp.GetServer(), "tencent-cos");
      ASSERT_EQ(multiupload_resp.GetXCosHashCrc64Ecma(),
                std::to_string(file_crc64_origin));

      // head object
      std::cout << "head object: " << object_name << std::endl;
      HeadObjectReq head_req(m_bucket_name, object_name);
      HeadObjectResp head_resp;
      CosResult head_result = m_client->HeadObject(head_req, &head_resp);
      ASSERT_TRUE(head_result.IsSucc());
      ASSERT_TRUE(!head_result.GetXCosRequestId().empty());
      ASSERT_EQ(head_resp.GetContentLength(), test_file_size);
      ASSERT_TRUE(!head_resp.GetDate().empty());
      ASSERT_EQ(head_resp.GetServer(), "tencent-cos");
      ASSERT_EQ(head_resp.GetXCosHashCrc64Ecma(),
                std::to_string(file_crc64_origin));

      // download object
      std::cout << "download object: " << object_name << std::endl;
      CosSysConfig::SetDownThreadPoolSize(thead_pool_size);
      CosSysConfig::SetDownSliceSize(part_size);
      std::string file_download = local_file + "_download";
      qcloud_cos::MultiGetObjectReq get_req(m_bucket_name, object_name,
                                         file_download);
      qcloud_cos::MultiGetObjectResp get_resp;
      CosResult get_result = m_client->MultiGetObject(get_req, &get_resp);
      // checkout common header
      ASSERT_TRUE(get_result.IsSucc());
      ASSERT_TRUE(!get_resp.GetXCosRequestId().empty());
      ASSERT_TRUE(!get_resp.GetConnection().empty());
      ASSERT_TRUE(!get_resp.GetDate().empty());
      ASSERT_EQ(get_resp.GetServer(), "tencent-cos");
      ASSERT_EQ(get_resp.GetXCosHashCrc64Ecma(),
                std::to_string(file_crc64_origin));
      ASSERT_EQ(file_crc64_origin, FileUtil::GetFileCrc64(file_download));
      ASSERT_EQ(FileUtil::GetFileMd5(local_file),
                FileUtil::GetFileMd5(file_download));

      // delete object
      std::cout << "delete object: " << object_name << std::endl;
      qcloud_cos::DeleteObjectReq del_req(m_bucket_name, object_name);
      qcloud_cos::DeleteObjectResp del_resp;
      CosResult del_result = m_client->DeleteObject(del_req, &del_resp);
      // checkout common header
      ASSERT_TRUE(del_result.IsSucc());
      ASSERT_TRUE(!del_resp.GetXCosRequestId().empty());
      ASSERT_TRUE(!del_resp.GetConnection().empty());
      ASSERT_TRUE(!del_resp.GetDate().empty());
      ASSERT_EQ(del_resp.GetServer(), "tencent-cos");

      // remove local file
      TestUtils::RemoveFile(local_file);
      TestUtils::RemoveFile(file_download);
    }
  }
}

TEST_F(ObjectOpTest, InvalidConfig) {
  {
    qcloud_cos::CosConfig config(123, "", "sk", "region");
    ASSERT_TRUE(config.GetAccessKey().empty());
    qcloud_cos::CosAPI cos(config);
    std::istringstream iss("put_obj_by_stream_string");
    PutObjectByStreamReq req("test_bucket", "test_object", iss);
    PutObjectByStreamResp resp;
    CosResult result = cos.PutObject(req, &resp);
    ASSERT_TRUE(!result.IsSucc());
    ASSERT_EQ(result.GetErrorMsg(),
              "Invalid access_key secret_key or region, please check your "
              "configuration");
  }
  {
    qcloud_cos::CosConfig config(123, "ak", "", "region");
    ASSERT_TRUE(config.GetSecretKey().empty());
    qcloud_cos::CosAPI cos(config);
    std::istringstream iss("put_obj_by_stream_string");
    PutObjectByStreamReq req("test_bucket", "test_object", iss);
    PutObjectByStreamResp resp;
    CosResult result = cos.PutObject(req, &resp);
    ASSERT_TRUE(!result.IsSucc());
    ASSERT_EQ(result.GetErrorMsg(),
              "Invalid access_key secret_key or region, please check your "
              "configuration");
  }
}
#endif

}  // namespace qcloud_cos
