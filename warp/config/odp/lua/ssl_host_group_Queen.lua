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
detection_name: SSL Group "Queen"
version: 13
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Audible.com' => 'Digital audio version for books, magazines, information and other entertainments.',
          'Bitcoin Forum' => 'Forums for discussing BitCoin mining and exchange.',
          'BoldChat' => 'Live Chat software for website.',
          'Ooyala' => 'Solution providers for Video analytics.',
          'FriendFinder' => 'Online friend finder and dating site.',
          'lynda.com' => 'Online education site focusing on aspects of web design.',
          'Bing Maps' => 'Microsoft online mapping and directions service.',
          'Windows Live SkyDrive' => 'Cloud based file hosting service.',
          'OpenSUSE' => 'Official website for OpenSUSE, Linux based OS.',
          'Starbucks' => 'Mobile application for a ubiquitous chain of coffee shops.',
          'Game Center' => 'Social gaming app for iOS.',
          'Microsoft Azure' => 'Cloud computing by Microsoft.',
          'DSW' => 'Designer Shoe Warehouse - branded footwear.',
          'Woopra' => 'Real time customer service and solutions.',
          'iTunes U' => 'Access to courses from the leading universities.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "ssl_host_group_Queen",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gSSLHostPatternList = {
	--Bing Maps
	{ 0, 1197, 'virtualearth.net' },
	--OpenSUSE
	{ 0, 2056, 'opensuse.org' },
	--DSW
	{ 0, 2059, 'dsw.com' },
	--BoldChat
	{ 0, 2067, 'boldchat.com' },
	--Woopra
	{ 0, 2069, 'woopra.com' },
	--Ooyala
	{ 0, 2072, 'ooyala.com' },
	--iTunes U
	{ 1, 2073, 'itunesu.itunes.apple.com' },
	--Bitcoin Forum
	{ 0, 2085, 'bitcointalk.org' },
	--lynda.com
	{ 0, 2086, 'lynda.com' },
	--Game Center
	{ 0, 2092, 'gc.apple.com' },
	--FriendFinder
	{ 0, 2093, 'friendfinder.com' },
	--Audible.com
	{ 0, 2094, 'audible.com' },
	--Microsoft Azure
	{ 0, 2111, 'windowsazure.com' },
	--Starbucks
	{ 1, 2112, 'starbucks.com' },
	--Windows Live SkyDrive
	{ 0, 911, 'skyapi.live.net' },
	{ 0, 911, 'storage.msn.com' },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3])
        end
    end
    return gDetector
end

function DetectorClean()
end
