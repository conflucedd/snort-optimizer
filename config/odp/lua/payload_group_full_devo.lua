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
detection_name: Payload Group Full "Devo"
version: 44
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'TwitPic' => 'Site for posting and sharing photos and videos on twitter.',
          'Afreeca' => 'Video streaming service based in South Korea.',
          'VKontakte' => 'Russian social networking service.',
          'Habbo' => 'Social networking site aimed at teenagers.',
          'iHeartRadio' => 'Website that provides streaming access to local and digital-only radio stations.',
          'Clarizen' => 'Work management and project management system.',
          'Mister Wong' => 'European social bookmarking service.',
          'GMX Mail' => 'German based webmail service.',
          'Webhard' => 'Online storage service available in Korean and English.',
          'SoundCloud' => 'Music platform for artists to upload and promote their music.',
          'Mibbit' => 'Web based chat client that supports IRC and Twitter.',
          'TwitchTV' => 'Justin.tv gaming specific livestreaming platform.',
          'Cyworld' => 'South Korean social networking service.',
          'BigUpload' => 'File hosting and sharing service.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_full_devo",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--Privax (Deprecated)
	--{ 0, 0, 0, 332, 46, "privax.us", "/", "http:", "", 1000 },
	--Schmedley (Deprecated)
	--{ 0, 0, 0, 336, 22, "schmedley.com", "/", "http:", "", 1004 },
	--SoundCloud
	{ 0, 0, 0, 339, 9, "soundcloud.us", "/", "http:", "", 1007 },
	--Steekr (Deprecated)
	--{ 0, 0, 0, 340, 9, "steekr.com", "/", "http:", "", 1008 },
	--Stickam (Deprecated)
	--{ 0, 0, 0, 341, 13, "stickam.com", "/", "http:", "", 1009 },
	--Tagoo (Deprecated)
	--{ 0, 0, 0, 344, 22, "tagoo.ru", "/", "http:", "", 1012 },
	--TurboUpload (Deprecated)
	--{ 0, 0, 0, 349, 9, "turboupload.com", "/", "http:", "", 1017 },
	--VKontakte
	{ 0, 0, 0, 350, 5, "vk.com", "/", "http:", "", 1018 },
	--Webhard
	{ 0, 0, 0, 352, 9, "webhard.co.kr", "/", "http:", "", 1020 },
	--Wixi (Deprecated)
	--{ 0, 0, 0, 355, 9, "wixi.com", "/", "http:", "", 1023 },
	--Woofiles (Deprecated)
	--{ 0, 0, 0, 356, 9, "woofiles.com", "/", "http:", "", 1024 },
	--BigUpload
	{ 0, 0, 0, 359, 9, "bigupload.net", "/", "http:", "", 1027 },
	--Clarizen
	{ 0, 0, 0, 360, 43, "clarizen.jp", "/", "http:", "", 1028 },
	--Rdio (Deprecated)
	--{ 0, 0, 0, 361, 13, "rdio.com", "/", "http:", "", 1029 },
	--Ubetoo (Deprecated)
	--{ 0, 0, 0, 362, 13, "ubetoo.com", "/", "http:", "", 1030 },
	--Joost (Deprecated)
	--{ 0, 0, 0, 368, 13, "joost.com", "/", "http:", "", 1036 },
	--Afreeca
	{ 0, 0, 0, 369, 13, "bizafreeca.com", "/", "http:", "", 1037 },
	{ 0, 0, 0, 369, 13, "afreecatv.com", "/", "http:", "", 1037 },
	--FileSonic (Deprecated)
	--{ 0, 0, 0, 371, 9, "filesonic.com", "/", "http:", "", 1039 },
	--Multiply (Deprecated)
	--{ 0, 0, 0, 375, 5, "multiply.com", "/", "http:", "", 1043 },
	--Sevenload (Deprecated)
	--{ 0, 0, 0, 376, 13, "sevenload.com", "/", "http:", "", 1044 },
	--Revver (Deprecated)
	--{ 0, 0, 0, 377, 13, "revver.com", "/", "http:", "", 1045 },
	--we7 (Deprecated)
	--{ 0, 0, 0, 379, 13, "we7.com", "/", "http:", "", 1047 },
	--{ 0, 0, 0, 379, 13, "we7.be", "/", "http:", "", 1047 },
	--Mibbit
	{ 0, 0, 0, 381, 10, "mibbit.fr", "/", "http:", "", 1049 },
	{ 0, 0, 0, 381, 10, "mibbitchat.de", "/", "http:", "", 1049 },
	--TwitchTV
	{ 0, 0, 0, 383, 13, "ext-twitch.tv", "/", "http:", "", 1051 },
	{ 0, 0, 0, 383, 13, "jtvnw.net", "/", "http:", "", 1051 },
	{ 0, 0, 0, 383, 13, "ttvnw.net", "/", "http:", "", 1051 },
	{ 0, 0, 0, 383, 13, "twitchcdn.net", "/", "http:", "", 1051 },
	{ 0, 0, 0, 383, 13, "twitchsvc.net", "/", "http:", "", 1051 },
	--eSnips (Deprecated)
	--{ 0, 0, 0, 388, 9, "esnips.com", "/", "http:", "", 1056 },
	--Files.to (Deprecated)
	--{ 0, 0, 0, 390, 9, "files.to", "/", "http:", "", 1058 },
	--FuFOX.com (Deprecated)
	--{ 0, 0, 0, 391, 9, "fufox.net", "/", "http:", "", 1059 },
	--TotoExpress (Deprecated)
	--{ 0, 0, 0, 393, 9, "totoexpress.com", "/", "http:", "", 1061 },
	--TwitPic
	{ 0, 0, 0, 395, 9, "twitpic.com", "/", "http:", "", 1063 },
	--oneview (Deprecated)
	--{ 0, 0, 0, 415, 14, "oneview.com", "/", "http:", "", 1083 },
	--{ 0, 0, 0, 415, 14, "oneview.de", "/", "http:", "", 1083 },
	--Badongo (Deprecated)
	--{ 0, 0, 0, 293, 9, "badongo.com", "/", "http:", "", 961 },
	--Cyworld
	{ 0, 0, 0, 295, 5, "cyworld.vn", "/", "http:", "", 963 },
	--Gowalla (Deprecated)
	--{ 0, 0, 0, 300, 5, "gowalla.com", "/", "http:", "", 968 },
	--GMX Mail
	{ 0, 0, 0, 309, 4, "gmx.net", "/", "http:", "", 977 },
	{ 0, 0, 0, 309, 4, "gmx.ch", "/", "http:", "", 977 },
	{ 0, 0, 0, 309, 4, "ui-portal.de", "/", "http:", "", 977 },
	{ 0, 0, 0, 309, 1, "gmx.com", "/", "http:", "", 977 },
	{ 0, 0, 0, 309, 1, "gmx.co.uk", "/", "http:", "", 977 },
	{ 0, 0, 0, 309, 1, "gmx.co", "/", "http:", "", 977 },
	--Habbo
	{ 0, 0, 0, 312, 5, "habbo.at", "/", "http:", "", 980 },
	{ 0, 0, 0, 312, 5, "habbo.be", "/", "http:", "", 980 },
	{ 0, 0, 0, 312, 5, "habbo.cl", "/", "http:", "", 980 },
	{ 0, 0, 0, 312, 5, "habbo.cn", "/", "http:", "", 980 },
	{ 0, 0, 0, 312, 5, "habbo.dk", "/", "http:", "", 980 },
	{ 0, 0, 0, 312, 5, "habbo.fi", "/", "http:", "", 980 },
	{ 0, 0, 0, 312, 5, "habbo.fr", "/", "http:", "", 980 },
	{ 0, 0, 0, 312, 5, "habbo.de", "/", "http:", "", 980 },
	{ 0, 0, 0, 312, 5, "habbo.it", "/", "http:", "", 980 },
	{ 0, 0, 0, 312, 5, "habbo.jp", "/", "http:", "", 980 },
	{ 0, 0, 0, 312, 5, "habbo.com", "/", "http:", "", 980 },
	--iHeartRadio
	{ 0, 0, 0, 316, 13, "iheart.com", "/", "http:", "", 984 },
	--Kickload (Deprecated)
	--{ 0, 0, 0, 322, 9, "kickload.com", "/", "http:", "", 990 },
	--Mister Wong
	{ 0, 0, 0, 331, 14, "mister-wong.de", "/", "http:", "", 999 },
	{ 0, 0, 0, 331, 14, "mister-wong.fr", "/", "http:", "", 999 },
	{ 0, 0, 0, 331, 14, "mister-wong.es", "/", "http:", "", 999 },
	{ 0, 0, 0, 331, 14, "mister-wong.ru", "/", "http:", "", 999 },
	{ 0, 0, 0, 331, 14, "mister-wong.cn", "/", "http:", "", 999 },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10])
        end
    end

    return gDetector
end

function DetectorClean()
end
