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
detection_name: Content Group Service ALPN mapping
version: 2
description: Group of ALPN to Service App detectors.
bundle_description: $VAR1 = {
          'HTTP/3' => 'Enhanced protocol for World wide web over QUIC.',
          'SMB over QUIC' => 'SMB over QUIC.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "content_group_alpn_service",
    proto =  DC.ipproto.udp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gAlpnServiceList = {
    --HTTP/3
    {4667, "h3"},
    --SMB over QUIC
    {4668, "smb"},
}

function DetectorInit(detectorInstance)
    gDetector = detectorInstance;
    if gDetector.addAlpnToServiceMapping then
        for i,v in ipairs(gAlpnServiceList) do
            gDetector:addAlpnToServiceMapping(v[1], v[2]);
        end
    end
    return gDetector;
end

function DetectorClean()
end
