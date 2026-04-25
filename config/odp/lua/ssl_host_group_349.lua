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
detection_name: SSL Group "349"
version: 1
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'IRCTC' => 'Official website for Indian Railway Catering and Tourism Corporation.',
          'Island Mob' => 'Official website for Island Mob which provides mobile services like, games, ringtones, videos and wallpapers.',
          'Kakaku' => 'Japanese website for price comparison on various products.',
          'KinoGo' => 'Russsian website for online movies.',
          'KissAnime' => 'Online streaming video.',
          'KASKUS' => 'Indonesian internet forum.',
          'La Repubblica' => 'Italian daily newspaper.',
          'KapanLagi' => 'Indonesia\'s internet forum.',
          'Kinopoisk' => 'Russian website for cinema related news and reviews.',
          'Myntra.com' => 'Indian online shopping site.',
          'The LAD Bible' => 'Entertainment news website.',
          'Kompas.com' => 'Indonesian newspaper portal.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_349",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {
    -- La Repubblica
    {0, 4344, 'repubblica.it', },
    -- The LAD Bible
    {0, 4343, 'ladbible.com', },
    -- Kompas.com
    {0, 4342, 'kompas.com', },
    -- KissAnime
    {0, 4341, 'kissanime.com.ru', },
    -- Kinopoisk
    {0, 4340, 'kinopoisk.ru', },
    -- KinoGo
    {0, 4339, 'kinogoo.by', },
    {0, 4339, 'kinogo.film', },
    {0, 4339, 'kinogo-net.org', },
    {0, 4339, 'kinogo.biz', },
    -- KASKUS
    {0, 4338, 'kaskus.co.id', },
    -- KapanLagi
    {0, 4337, 'kapanlagi.com', },
    -- Kakaku
    {0, 4336, 'kakaku.com', },
    -- Myntra.com
    {0, 4335, 'jabong.com', },
    {0, 4335, 'myntra.com', },
    -- Island Mob
    {0, 4334, 'islandmob.com', },
    -- IRCTC
    {0, 4333, 'irctc.co.in', },
}

gSSLCnamePatternList = {
    -- La Repubblica
    {0, 4344, 'repubblica.it', },
    -- The LAD Bible
    {0, 4343, 'ladbible.com', },
    -- Kompas.com
    {0, 4342, 'kompas.com', },
    -- KissAnime
    {0, 4341, 'kissanime.com.ru', },
    -- Kinopoisk
    {0, 4340, 'kinopoisk.ru', },
    -- KinoGo
    {0, 4339, 'kinogoo.by', },
    {0, 4339, 'kinogo.film', },
    {0, 4339, 'kinogo-net.org', },
    {0, 4339, 'kinogo.biz', },
    -- KASKUS
    {0, 4338, 'kaskus.co.id', },
    -- KapanLagi
    {0, 4337, 'kapanlagi.com', },
    -- Kakaku
    {0, 4336, 'kakaku.com', },
    -- Myntra.com
    {0, 4335, 'jabong.com', },
    {0, 4335, 'myntra.com', },
    -- Island Mob
    {0, 4334, 'islandmob.com', },
    -- IRCTC
    {0, 4333, 'irctc.co.in', },
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
