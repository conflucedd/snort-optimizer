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
detection_name: Payload Group "lorde"
version: 8
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Google Inbox' => 'An alternate Gmail interface provided by Google.',
          'ZenMate' => 'Proxy and security add-on to browser.',
          'Venmo' => 'A free digital wallet that lets you make and share payments with friends.',
          'Google Sign in' => 'Signin portal for Google apps and services.',
          'DingDing' => 'Instant messaging & Collaboration software.',
          'Yandex Images' => 'Yandex image search.'
        };

--]]

require "DetectorCommon"



local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_lorde",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {
    -- ZenMate
    { 0, 0, 0, 1890, 46, "zenmate.com", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "zenguard.biz", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "zcdn.de", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "zenguard.zendesk.com", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "coffey-navy.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "barrett-aqua.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "davis-decker-black.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "bauer-henry-black.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "dean-fuchsia.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "gonzalez-fuchsia.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "wilson-white.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "terry-hale-olive.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "young-aqua.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "davis-woods-gray.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "davis-white.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "edwards-white.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "holt-navy.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "jackson-aqua.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "ramirez-white.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "rodriguez-simon-yellow.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "chambers-silver.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "lawson-olive.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "wolf-fuchsia.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "gonzalez-church-blue.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "morgan-ray-green.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "morales-smith-green.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "pierce-perez-blue.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "buchanan-williams-yellow.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "klein-maroon.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "simpson-aqua.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "huffman-purple.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "payne-silver.ml", "/", "http:", "", 3994},
    { 0, 0, 0, 1890, 46, "davis-silver.ml", "/", "http:", "", 3994},

    --DingDing
    { 0, 527, 16, 1891, 49, "dingtalk.com", "/", "http:", "", 4163},
    { 0, 527, 16, 1891, 49, "dingtalkapps.com", "/", "http:", "", 4163},

    --Google Sign in
    { 0, 0, 0, 1892, 22, "accounts.google.com", "/", "http:", "", 4385},

    --Venmo
    { 0, 529, 15, 1893, 39, "venmo.com", "/", "http:", "", 4387},

    -- Google Inbox
    { 0, 0, 0, 1894, 4, "inbox.google.com", "/", "http:", "", 4488},
    { 0, 0, 0, 1894, 4, "google.com", "/inbox", "http:", "", 4488},

    --Yandex Images
    { 0, 0, 0, 1896, 22, "yandex.com", "/images", "http:", "", 4060},
    { 0, 0, 0, 1896, 22, "img.fotki.yandex", "/", "http:", "", 4060},
    { 0, 0, 0, 1896, 22, "images.yandex", "/", "http:", "", 4060},
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    --DingDing
    gDetector:addHttpPattern(2, 5, 0, 527, 16, 0, 0, 'DingTalk', 4163);

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

