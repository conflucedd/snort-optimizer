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
detection_name: SSL Group "Lorde"
version: 12
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'TOR' => 'The Onion Router. A client which allows a user to send and relay internet traffic anonymously.',
          'Funshion' => 'Chinese site for online games, videos, and shopping.',
          'Sports Illustrated' => 'Web portal for sports news and updates.',
          'Google Inbox' => 'An alternate Gmail interface provided by Google.',
          'Yandex Images' => 'Yandex image search.',
          'FreeCast' => 'Peer-to-peer streaming.',
          'DingDing' => 'Instant messaging & Collaboration software.',
          'Venmo' => 'A free digital wallet that lets you make and share payments with friends.',
          'ZenMate' => 'Proxy and security add-on to browser.',
          'Google Sign in' => 'Signin portal for Google apps and services.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_lorde",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--detectorType(0-> Web, 1->Client),  AppId, SSLPattern
gSSLHostPatternList = {

    --Freecast
    { 0, 163, 'freecast.live'},
    { 0, 163, 'freecast.com'},

    --ZenMate
    { 0, 3994, 'zenmate.com'},
    { 0, 3994, 'zenguard.biz'},
    { 0, 3994, 'zcdn.de'},
    { 0, 3994, 'coffey-navy.ml'},
    { 0, 3994, 'barrett-aqua.ml'},
    { 0, 3994, 'davis-decker-black.ml'},
    { 0, 3994, 'bauer-henry-black.ml'},
    { 0, 3994, 'dean-fuchsia.ml'},
    { 0, 3994, 'gonzalez-fuchsia.ml'},
    { 0, 3994, 'wilson-white.ml'},
    { 0, 3994, 'terry-hale-olive.ml'},
    { 0, 3994, 'young-aqua.ml'},
    { 0, 3994, 'davis-woods-gray.ml'},
    { 0, 3994, 'davis-white.ml'},
    { 0, 3994, 'edwards-white.ml'},
    { 0, 3994, 'holt-navy.ml'},
    { 0, 3994, 'jackson-aqua.ml'},
    { 0, 3994, 'ramirez-white.ml'},
    { 0, 3994, 'rodriguez-simon-yellow.ml'},
    { 0, 3994, 'chambers-silver.ml'},
    { 0, 3994, 'lawson-olive.ml'},
    { 0, 3994, 'wolf-fuchsia.ml'},
    { 0, 3994, 'gonzalez-church-blue.ml'},
    { 0, 3994, 'morgan-ray-green.ml'},
    { 0, 3994, 'morales-smith-green.ml'},
    { 0, 3994, 'pierce-perez-blue.ml'},
    { 0, 3994, 'buchanan-williams-yellow.ml'},
    { 0, 3994, 'klein-maroon.ml'},
    { 0, 3994, 'simpson-aqua.ml'},
    { 0, 3994, 'huffman-purple.ml'},
    { 0, 3994, 'payne-silver.ml'},
    { 0, 3994, 'davis-silver.ml'},
    { 0, 3994, 'zenguard.zendesk.com'},

    --DingDing
    { 0, 4163, 'im.dingtalk.com'},
    { 1, 4163, 'dingtalk.com'},
    { 1, 4163, 'dingtalkapps.com'},

    --TOR
    { 0, 473, 'torproject.org'},

    --Google Sign in
    { 0, 4385, 'accounts.google.com'},

    -- Funshion
    { 0, 2391, 'fun.tv' },
    { 0, 2391, 'funshion.com' },

    --Venmo
    { 1, 4387, 'api.venmo.com'},
    { 0, 4387, 'venmo.com'},

    -- Sports Illustrated
    {0, 1456, 'si.com'},

    -- Google Inbox
    { 0, 4488, 'inbox.google.com'},

    -- Yandex Images
    { 0, 4060, 'img.fotki.yandex'},
    { 0, 4060, 'images.yandex'},
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
