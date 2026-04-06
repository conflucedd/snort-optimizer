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
detection_name: Payload Group "349"
version: 3
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'The LAD Bible' => 'Entertainment news website.',
          'Island Mob' => 'Official website for Island Mob which provides mobile services like, games, ringtones, videos and wallpapers.',
          'Myntra.com' => 'Indian online shopping site.',
          'KapanLagi' => 'Indonesia\'s internet forum.',
          'IRCTC' => 'Official website for Indian Railway Catering and Tourism Corporation.',
          'Kinopoisk' => 'Russian website for cinema related news and reviews.',
          'KinoGo' => 'Russsian website for online movies.',
          'La Repubblica' => 'Italian daily newspaper.',
          'KASKUS' => 'Indonesian internet forum.',
          'KissAnime' => 'Online streaming video.',
          'Kakaku' => 'Japanese website for price comparison on various products.',
          'Kompas.com' => 'Indonesian newspaper portal.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_347",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {
    -- La Repubblica
    { 0, 0, 0, 2036, 1, "repubblica.it", "/", "http:", "", 4344},
    { 0, 0, 0, 2036, 1, "repstatic.it", "/", "http:", "", 4344},
    -- The LAD Bible
    { 0, 0, 0, 2037, 1, "ladbible.com", "/", "http:", "", 4343},
    -- Kompas.com
    { 0, 0, 0, 2038, 1, "kompas.com", "/", "http:", "", 4342},
    -- KissAnime
    { 0, 0, 0, 2039, 1, "kissanime.com.ru", "/", "http:", "", 4341},
    { 0, 0, 0, 2039, 1, "anmedm.com", "/", "http:", "", 4341},
    -- Kinopoisk
    { 0, 0, 0, 2040, 1, "kinopoisk.ru", "/", "http:", "", 4340},
    -- KinoGo
    { 0, 0, 0, 2041, 1, "kinogoo.by", "/", "http:", "", 4339},
    { 0, 0, 0, 2041, 1, "kinogo.film", "/", "http:", "", 4339},
    { 0, 0, 0, 2041, 1, "kinogo-net.org", "/", "http:", "", 4339},
    { 0, 0, 0, 2041, 1, "kinogo.biz", "/", "http:", "", 4339},
    -- KASKUS
    { 0, 0, 0, 2042, 1, "kaskus.co.id", "/", "http:", "", 4338},
    { 0, 0, 0, 2042, 1, "kaskus.id", "/", "http:", "", 4338},
    -- KapanLagi
    { 0, 0, 0, 2043, 1, "kapanlagi.com", "/", "http:", "", 4337},
    { 0, 0, 0, 2043, 1, "klimg.com", "/", "http:", "", 4337},
    -- Kakaku
    { 0, 0, 0, 2044, 1, "kakaku.com", "/", "http:", "", 4336},
    -- Myntra.com
    { 0, 0, 0, 2045, 1, "jabong.com", "/", "http:", "", 4335},
    { 0, 0, 0, 2045, 1, "myntra.com", "/", "http:", "", 4335},
    { 0, 0, 0, 2045, 1, "myntassets.com", "/", "http:", "", 4335},
    -- Island Mob
    { 0, 0, 0, 2046, 1, "islandmob.com", "/", "http:", "", 4334},
    -- IRCTC
    { 0, 0, 0, 2047, 1, "irctc.co.in", "/", "http:", "", 4333},
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end
