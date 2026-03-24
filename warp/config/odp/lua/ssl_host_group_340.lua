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
detection_name: SSL Group "340"
version: 5
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'DotVPN' => 'A VPN Tunneling app.',
          'GoDaddy' => 'Domain registrar.',
          'ExpressVPN' => 'A paid VPN platform with desktop and mobile apps.',
          'Yandex Music' => 'Yandex music downloads.',
          'Zynga Poker' => 'Poker game available on social network sites and mobile devices.',
          'TurboVPN' => 'A VPN client on mobile devices.',
          'BlueStacks' => 'An app player that runs mobile apps on laptops and desktop machines.',
          'Microsoft Excel' => 'Microsoft online spreadsheet software.',
          'Angry Birds' => 'Catapult game.',
          'Steam' => 'Massive gaming and communications platform.',
          'Instagram Media' => 'Traffic generated while viewing images and videos in Instagram.',
          'Gom VPN' => 'Browser plugin based VPN.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_340",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {

    --GoDaddy Internet Domain registrar
    {0, 1373, 'godaddy.com' },
    -- BlueStacks
    {0, 3980, 'bluestacks.com' },
    --Zynga poker
    {0, 910, 'zyngapoker.com' },
    --AngryBirds
    {0, 1162, 'angrybirds.com' },
    --Yandex Music
    {0, 4065, 'music.yandex.ru' },
    --Turbo VPN
    {0, 4140, 'turbovpn.co' },
    {0, 4140, 'turbo-vpn.en.uptodown.com' },
    --ExpressVPN
    {0, 4519, 'expressvpn.com' },
    --DotVPN
    {0, 4082, 'dotvpn.com' },
    --Gom VPN
    {0, 4028, 'getgom.com' },
    --Instagram Media
    {0, 4639, 'cdninstagram.com' },
    --Steam
    {0, 1086, 'steampowered.com' },
    {0, 1086, 'steamcdn-a.akamaihd.net' },
    {0, 1086, 'steamstore-a.akamaihd.net' },
    {0, 1086, 'steamstatic.com' },

    -- Microsoft Excel
    {0, 2288, 'us4b-excel-collab.officeapps.live.com', },
    {0, 2288, 'excel.officeapps.live.com', },
    {0, 2288, 'c1-excel-15.cdn.office.net', },
    {0, 2288, 'c1h-excel-15.cdn.office.net', },
}

gSSLCnamePatternList = {

    -- BlueStacks
    {0, 3980, 'bluestacks.com' },
    --Zynga poker
    {0, 910, 'zyngapoker.com' },
    --AngryBirds
    {0, 1162, 'angrybirds.com' },
    --Turbo VPN
    {0, 4140, 'turbovpn.co' },
    --ExpressVPN
    {0, 4519, 'expressvpn.com' },
    --DotVPN
    {0, 4082, 'DotVPN' },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end

    if gDetector.addSSLCnamePattern then
        for i,v in ipairs(gSSLCnamePatternList) do
            gDetector:addSSLCnamePattern(v[1],v[2],v[3]);
        end
    end

    return gDetector;
end

function DetectorClean()
end
