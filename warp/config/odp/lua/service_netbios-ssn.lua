--[[
# Copyright 2001-2014 Cisco Systems, Inc. and/or its affiliates. All rights
# reserved.
#
# This file contains proprietary Detector Content created by Cisco Systems,
# Inc. or its affiliates ("Cisco") and is distributed under the GNU General
# Public License, v2 (the "GPL").  This file may also include Detector Content
# contributed by third parties. Third party contributors are identified in the
# "authors" file.  The Detector Content created by Cisco is owned by, and
# remains the property of, Cisco.  Detector Content from third party
# contributors is owned by, and remains the property of, such third parties and
# is distributed under the GPL.  The term "Detector Content" means specifically
# formulated patterns and logic to identify applications based on network
# traffic characteristics, comprised of instructions in source code or object
# code form (including the structure, sequence, organization, and syntax
# thereof), and all documentation related thereto that have been officially
# approved by Cisco.  Modifications are considered part of the Detector
# Content.
--]]
--[[
detection_name: NetBIOS-ssn (SMB)
version: 10
description: Netbios session service, also known as SMB.
bundle_description: $VAR1 = {
          'SMBv3-encrypted' => 'Server Message Block version 3, encrypted traffic.',
          'SMBv3-unencrypted' => 'Server Message Block version 3, more recent SMB dialects including SMB 3.0, SMB 3.0.1, and SMB 3.1.1.',
          'SMBv1' => 'Server Message Block version 1, a set of early SMB dialects including SMB, SMB1, and CIFS.',
          'NetBIOS-ssn (SMB)' => 'Netbios session service, also known as SMB.',
          'SMBv2' => 'Server Message Block version 2. This set of SMB dialects includes SMB 2.0 and SMB 2.1.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon
local FT = flowTrackerModule

gServiceId = 17
gServiceName = 'NetBIOS-ssn (SMB)'
gDetector = nil

DetectorPackageInfo = {
    name =  "NetBIOS-ssn (SMB)",
    proto =  DC.ipproto.tcp,
    server = {
        init =  'DetectorInit',
        validate =  'DetectorValidator',
        fini = 'DetectorFini',
    }
}

gSfAppIdSMB = 755
gSfAppIdSMBv1 = 4645
gSfAppIdSMBv2 = 4646
gSfAppIdSMBv3_encrypted = 4647
gSfAppIdSMBv3_unencrypted = 4665

gPatterns = {
    smbanner1 = { "\255SMB", 4, gSfAppIdSMB},
    smbanner2 = { "\254SMB", 4, gSfAppIdSMB},
    smbanner3 = { "\253SMB", 4, gSfAppIdSMB},
    nbss_response = { "\130", 0, gSfAppIdSMB},
    smbv1_status_success = { "\000\000\000\000", 9, gSfAppIdSMB},
    smbv1_status_mpr = { "\022\000\000\192", 9, gSfAppIdSMB},
    smbv2_session_setup = { "\001\000", 16, gSfAppIdSMB},
    smbv2_struct_size_9 = { "\009\000", 68, gSfAppIdSMB},
    smbv2_ntlmssp_challenge = {"NTLMSSP\000\002\000\000\000", 107, gSfAppIdSMB},
}

gFastPatterns = {
    {DC.ipproto.tcp, gPatterns.smbanner1},
    {DC.ipproto.tcp, gPatterns.smbanner2},
    {DC.ipproto.tcp, gPatterns.smbanner3},
}

gPorts = {
    {DC.ipproto.tcp, 139},
    {DC.ipproto.tcp, 445},
}

gAppRegistry = {
	{gSfAppIdSMB, 1},
    {gSfAppIdSMBv1, 1},
    {gSfAppIdSMBv2, 1},
    {gSfAppIdSMBv3_encrypted, 1},
    {gSfAppIdSMBv3_unencrypted, 1},
}

function serviceInProcess(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)
    if not flowFlag or flowFlag == 0 then
        gDetector:inProcessService()
    end
    DC.log(gDetector,'%s: Inprocess, packetCount: %d\n', gServiceName, context.packetCount)
    return DC.serviceStatus.inProcess
end

function serviceSuccess(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)
    if context.payload_id and context.add_payload then
        DC.log(gDetector,"%s: adding payload %d\n", gServiceName, context.payload_id)
        gDetector:service_analyzePayload(context.payload_id)
    end
    if not flowFlag or flowFlag == 0 then
        gDetector:addService(gServiceId, "", "", gSfAppIdSMB)
    end
    DC.log(gDetector,'%s: Detected, packetCount: %d\n', gServiceName, context.packetCount)
    return DC.serviceStatus.success
end

function serviceFail(context)
    local flowFlag = context.detectorFlow:getFlowFlag(DC.flowFlags.serviceDetected)
    if not flowFlag or flowFlag == 0 then
        gDetector:failService()
    end
    context.detectorFlow:clearFlowFlag(DC.flowFlags.continue)
    DC.log(gDetector,'%s: Failed, packetCount: %d\n', gServiceName, context.packetCount)
    return DC.serviceStatus.nomatch
end

function registerPortsPatterns()
    for i,v in ipairs(gPorts) do
        gDetector:addPort(v[1], v[2])
    end
    for i,v in ipairs(gFastPatterns) do
        if (gDetector:registerPattern(v[1], v[2][1], #v[2][1], v[2][2], v[2][3]) ~= 0) then
            DC.log(gDetector,'%s: register pattern failed for %s\n', gServiceName,v[2][1])
        else
            DC.log(gDetector,'%s: register pattern successful for %s\n', gServiceName,v[2][1])
        end
    end
	for i,v in ipairs(gAppRegistry) do
		pcall(function () gDetector:registerAppId(v[1],v[2]) end)
	end
end

local function get_smbv1_domain(size)
    DC.log(gDetector,"%s: checking smbv1 domain, size %d", gServiceName, size)
    if size >= 37 and
        (DC.checkPattern(gDetector, gPatterns.smbv1_status_success) or
         DC.checkPattern(gDetector, gPatterns.smbv1_status_mpr)) then

        -- make sure this is "negotiate protocol" or "session setup andx" response
        local smb_command_raw = gDetector:getSubstr(8, 1)
        local smb_command = DC.reverseBinaryStringToNumber(smb_command_raw, 1)
        DC.log(gDetector,"%s: smb_command %d", gServiceName, smb_command)
        if smb_command ~= 115 and smb_command ~= 114 then
            return nil
        end

        -- figure out if unicode is used or not
        local use_unicode_raw = gDetector:getSubstr(15, 1)
        local use_unicode_code = DC.reverseBinaryStringToNumber(use_unicode_raw, 1)
        DC.log(gDetector,"%s: use_unicode_code %d", gServiceName, use_unicode_code)
        local use_unicode = nil
        if use_unicode_code >= 128 then
            DC.log("%s: use_unicode set to 1", gServiceName)
            use_unicode = 1
        end

        -- index of word count is 36
        local wc_raw = gDetector:getSubstr(36, 1)
        local wc = DC.reverseBinaryStringToNumber(wc_raw, 1)
        DC.log(gDetector,"%s: wc %d", gServiceName, wc)

       -- the byte count should be immediately beyond the stuff within the wc; check packet size
        local byte_count_index = wc * 2 + 1 + 36
        DC.log(gDetector,"%s: byte_count_index %d", gServiceName, byte_count_index)
        if size < byte_count_index + 2 then
            return nil
        end

        local byte_count_raw = gDetector:getSubstr(byte_count_index, 2)
        local byte_count = DC.reverseBinaryStringToNumber(byte_count_raw, 2)
        DC.log(gDetector,"%s: byte_count %d\n", gServiceName, byte_count)
        if size < byte_count_index + 2 + byte_count then
            return nil
        end

        local domain_index = nil
        -- smb_command 114 is Negotiate Protocol response
        if smb_command == 114 then
            local challenge_len_raw = gDetector:getSubstr(byte_count_index - 1, 1)
            local challenge_len = DC.reverseBinaryStringToNumber(challenge_len_raw, 1)
            DC.log(gDetector,"%s: challenge_len %d\t", gServiceName, challenge_len)
            if challenge_len == 0 then
                return nil
            end
            -- the length should be within the bounds of the byte count
            domain_index = byte_count_index + 2 + challenge_len

        -- otherwise we know it's a Session Setup Andx response; which we handle one of two ways
        -- based on the specific wc value: wc 3 means there is no security blob
        elseif wc == 3 then
            DC.log(gDetector,"%s: WC is 3\t", gServiceName)
            domain_index = byte_count_index + 2

        -- if wc is 4, then we have a security blob and we can find its length
        elseif wc == 4 then
            local sec_len_raw = gDetector:getSubstr(byte_count_index - 2, 2)
            local sec_len = DC.reverseBinaryStringToNumber(sec_len_raw, 2)
            DC.log(gDetector,"%s: sec_len %d\t", gServiceName, sec_len)
            domain_index = byte_count_index + 2 + sec_len
        else
            return nil
        end

        DC.log(gDetector,"%s: domain_index %d\n", gServiceName, domain_index)

        if size < domain_index + 1 + 3 then
            return nil
        end
        local smb_domain = nil
        if use_unicode then
            local first_nul_index = gDetector:substrIndex(domain_index, "\x00\x00\x00")
            if first_nul_index == nil or first_nul_index + 3 > size then
                return nil
            end

            local second_nul_index = gDetector:substrIndex(first_nul_index + 3, "\x00\x00\x00")
            if second_nul_index == nil or second_nul_index + 3 > size then
                return nil
            end

            local third_nul_index = gDetector:substrIndex(second_nul_index + 3, "\x00\x00\x00")
            if third_nul_index == nil or third_nul_index + 3 > size then
                return nil
            end

            local domain_start = second_nul_index + 3
            local domain_len = third_nul_index + 1 - domain_start
            local wide_smb_domain = gDetector:getSubstr(domain_start, domain_len)
            smb_domain = string.gsub(wide_smb_domain, "%z", "")

        else
            local matched, smb_domain = gDetector:getPcreGroups(".*\000.*\000(.*)\000", domain_index)
        end
        DC.log(gDetector,"%s: smb_domain %s\n", gServiceName, smb_domain)

        return smb_domain

    else
        return nil
    end
end

local function get_smbv2_domain(size)
    -- packet has 164 bytes of content before any variable-sized fields. So that's our
    -- minimum packet size, and the index we use before our next size check
    local static_content_size = 164
    DC.log(gDetector, "%s: checking smbv2 domain, size %d\n", gServiceName, size)
    if size >= static_content_size and DC.checkPattern(gDetector, gPatterns.smbv2_session_setup) and
        DC.checkPattern(gDetector, gPatterns.smbv2_struct_size_9) and
        DC.checkPattern(gDetector, gPatterns.smbv2_ntlmssp_challenge) then

        DC.log(gDetector, "struct_size is 9 and there is an ntlmssp challenge\n")
        local info_item_len_raw = gDetector:getSubstr(119, 2)
        local info_item_len = DC.reverseBinaryStringToNumber(info_item_len_raw, 2)
        local attribute_buf_index = static_content_size - 1 + info_item_len
        DC.log(gDetector, "%s: info_item_len is %d, so attribute_buf_index is %d\n", gServiceName, info_item_len, attribute_buf_index)

        if size < attribute_buf_index + 1 + 4 then
            return nil
        end
        local nb_domain_flag_index = gDetector:substrIndex(attribute_buf_index, "\002\000")
        local nb_domain_len_raw = gDetector:getSubstr(nb_domain_flag_index + 2, 2)
        local nb_domain_len = DC.reverseBinaryStringToNumber(nb_domain_len_raw, 2)
        DC.log(gDetector, "%s: nb_domain_flag_index is %d and nb_domain_len is %d\n", gServiceName, nb_domain_flag_index, nb_domain_len)

        if size < nb_domain_flag_index + 1 + 4 + nb_domain_len then
            return mil
        end
        local wide_smb_domain = gDetector:getSubstr(nb_domain_flag_index + 4, nb_domain_len)
        smb_domain = string.gsub(wide_smb_domain, "%z", "")
        DC.log(gDetector, "%s: smb_domain %s\n", gServiceName, smb_domain)

        return smb_domain
    else
        return nil
    end
end

local function check_smbv3_dialect(size)
    if size >= 18 then
        -- we need the smb2 header length to find our dialect field
        local match, smb2_hdr_len_raw = gDetector:getPcreGroups("(..)", 8)
        local smb2_hdr_len = DC.reverseBinaryStringToNumber(smb2_hdr_len_raw, 2)
        -- we are only interested in Negotiate Protocol Response packets - the cmd is "0"
        local match, smb2_cmd_raw = gDetector:getPcreGroups("(..)", 16)
        local smb2_cmd = DC.reverseBinaryStringToNumber(smb2_cmd_raw, 2)
        DC.log(gDetector,"%s: check_smbv3_dialect: smb2 header size %d, total size %d, smb2_cmd %d\n",
            gServiceName, smb2_hdr_len, size, smb2_cmd)
        local dialect_index = 4 + smb2_hdr_len + 5
        DC.log(gDetector,"%s: dialect index is %d\n", gServiceName, dialect_index)
        if smb2_cmd == 0 and size > dialect_index then
            local match, dialect_raw = gDetector:getPcreGroups("(.)", dialect_index)
            local dialect = DC.binaryStringToNumber(dialect_raw, 1)
            DC.log(gDetector,"%s: dialect is %d\n", gServiceName, dialect)
            if dialect >= 3 then
                return 1
            end
        end
    end
    return nil
end

function DetectorInit(detectorInstance)
    gDetector = detectorInstance
    DC.log(gDetector,'%s:DetectorInit()\n', gServiceName)
    gDetector:init(gServiceName, 'DetectorValidator', 'DetectorFini')
    registerPortsPatterns()
    return gDetector
end

function DetectorValidator()
    local context = {}
    context.detectorFlow = gDetector:getFlow()
    context.packetDataLen = gDetector:getPacketSize()
    context.packetDir = gDetector:getPacketDir()
    context.flowKey = context.detectorFlow:getFlowKey()
    context.packetCount = gDetector:getPktCount()
    local size = context.packetDataLen
    local dir = context.packetDir
    local flowKey = context.flowKey

    DC.log(gDetector,'%s:DetectorValidator(): packetCount %d, dir %d, size %d\n',
        gServiceName, context.packetCount, dir, size)

    if size == 0 or dir == 0 then
        return serviceInProcess(context)
    end

    local rft = FT.getFlowTracker(flowKey)
    if not rft then
        rft = FT.addFlowTracker(flowKey, {nbss_count = 0})
    end

    if dir == 1 and size >= 4 then
        local matched, len_raw = gDetector:getPcreGroups('.(...)',0)
        local len = DC.binaryStringToNumber(len_raw, 3)
        DC.log(gDetector,"len %d, size-4 %d\n", len, size-4)
        if (len == size-4) then
            if DC.checkPattern(gDetector, gPatterns.nbss_response) then
                DC.log(gDetector,"NBSS packet\n")
                return serviceInProcess(context)
            -- check the header to determine SMB version
            elseif size >= 10 and DC.checkPattern(gDetector, gPatterns.smbanner1) then
                DC.log(gDetector,"detected SMBv1\n")
                context.payload_id = gSfAppIdSMBv1
                if (gDetector.service_addNetbiosDomain and gDetector.substrIndex and
                    gDetector.getSubstr and not rft.nb_domain) then
                    rft.nb_domain = get_smbv1_domain(size)
                    if rft.nb_domain then
                        DC.log(gDetector,"smb1 rft.nb_domain is %s\n", rft.nb_domain)
                        gDetector:service_addNetbiosDomain(rft.nb_domain)
                    end
                end
            elseif size >= 10 and DC.checkPattern(gDetector, gPatterns.smbanner2) then
                DC.log(gDetector,"detected SMBv2\n")
                if (gDetector.service_addNetbiosDomain and gDetector.substrIndex and
                    gDetector.getSubstr and not rft.nb_domain) then
                    rft.nb_domain = get_smbv2_domain(size)
                    if rft.nb_domain then
                        DC.log(gDetector,"smb2 rft.nb_domain is %s\n", rft.nb_domain)
                        gDetector:service_addNetbiosDomain(rft.nb_domain)
                    end
                end
                if rft.smbv3_dialect or check_smbv3_dialect(size) then
                    DC.log(gDetector,"dialect SMBv3\n")
                    rft.smbv3_dialect = 1
                    context.payload_id = gSfAppIdSMBv3_unencrypted
                    context.add_payload = 1
                else
                    DC.log(gDetector,"dialect IS NOT SMBv3\n")
                    context.payload_id = gSfAppIdSMBv2
                end
            elseif size >= 10 and DC.checkPattern(gDetector, gPatterns.smbanner3) then
                DC.log(gDetector,"detected SMBv3 banner\n")
                rft.smbv3_dialect = 1
                context.payload_id = gSfAppIdSMBv3_encrypted
                context.add_payload = 1
            else
                -- fail if we don't see one of those headers
                return serviceFail(context)
            end

            rft.nbss_count = rft.nbss_count + 1
            DC.log(gDetector,"rft.nbss_count %d\n", rft.nbss_count)
            if rft.nbss_count >= 5 then
                context.detectorFlow:clearFlowFlag(DC.flowFlags.continue)
                context.add_payload = 1
                return serviceSuccess(context)
            else
                context.detectorFlow:setFlowFlag(DC.flowFlags.continue)
                return serviceSuccess(context)
            end
        end
    end

    return serviceFail(context)
end

function DetectorFini()
end

