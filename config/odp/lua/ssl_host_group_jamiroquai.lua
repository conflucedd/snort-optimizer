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
detection_name: SSL Group "jamiroquai"
version: 6
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'HIKE' => 'Mobile App for Instant Messaging.',
          'Ngrok' => 'Multiplatform tunnelling, reverse proxy software.',
          'Slotomania' => 'Facebook slots game.',
          'Google Play' => 'Google Play Store for Android applications.',
          'Paybill' => 'Online secure payment and billing service.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_jamiroquai",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--detectorType(0-> Web, 1->Client),  AppId, SSLPattern
gSSLHostPatternList = {

    --Google Play
    { 0, 2469, 'play.google.com' },
    { 0, 2469, 'play.googleapis.com' },

    --HIKE Messenger
    { 1, 4132, 'hike.in'},
    --Ngrok
    { 1, 4134, 'ngrok.com'},
    { 1, 4134, 'korgn.su.lennut.com'},
    { 0, 4134, 'ngrok.io'},
    --Paybill
    { 0, 4135, 'paybill.com'},
    --Slotomania
    { 0, 1243, 'playtika.com'},
    { 0, 1243, 'slotomania.com'},
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

