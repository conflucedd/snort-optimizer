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
detection_name: Payload Group Full "Oingo"
version: 16
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Bizrate' => 'Lists best deals for online shopping.',
          'Redbox' => 'Online movie rental and video streaming.',
          'King.com' => 'Web-based gaming.',
          'Cheezburger' => 'Hang-out place for funny Photos and stories.',
          'theCHIVE' => 'Funny photos and videos.',
          'MTv' => 'Official website for MTv.',
          'Cute Overload' => 'Pictures,videos and stories about Animals.',
          'LivePerson' => 'Online Marketing and Web analytics service provider.',
          'Rotten Tomatoes' => 'Online information and reviews about new films.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_full_Oingo",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--King.com
	{ 0, 0, 0, 937, 20, "king.com", "/", "http:", "", 1599 },
	--Bizrate
	{ 0, 0, 0, 890, 22, "bizrate-images.com", "/", "http:", "", 1782 },
	--Cute Overload
	{ 0, 0, 0, 892, 22, "cuteoverload.files.wordpress.com", "/", "http:", "", 1784 },
	--Cheezburger
	{ 0, 0, 0, 893, 22, "cheezdev.com", "/", "http:", "", 1785 },
	{ 0, 0, 0, 893, 22, "chzbgr.com", "/", "http:", "", 1785 },
	--theCHIVE
	{ 0, 0, 0, 896, 22, "thethrottle.thechive.com", "/", "http:", "", 1788 },
	{ 0, 0, 0, 896, 22, "chivethethrottle.files.wordpress.com", "/", "http:", "", 1788 },
	{ 0, 0, 0, 896, 22, "shechive.files.wordpress.com", "/", "http:", "", 1788 },
	{ 0, 0, 0, 896, 22, "thebrigade.com", "/", "http:", "", 1788 },
	{ 0, 0, 0, 896, 22, "theberry.com", "/", "http:", "", 1788 },
	{ 0, 0, 0, 896, 22, "cdn.thechivemobile.com.edgesuite.net", "/", "http:", "", 1788 },
	--LivePerson
	{ 0, 0, 0, 908, 22, "liveperson.net", "/", "http:", "", 1797 },
	--Rotten Tomatoes
	{ 0, 0, 0, 912, 22, "rottentomatoescdn.com", "/", "http:", "", 1803 },
	--MTv
	{ 0, 0, 0, 914, 22, "mtvnimages.com", "/", "http:", "", 1805 },
	{ 0, 0, 0, 914, 22, "mtvnservices.com", "/", "http:", "", 1805 },
	{ 0, 0, 0, 914, 22, "mtvn.demdex.net", "/", "http:", "", 1805 },
	--Wii News Channel (Deprecated)
	--{ 0, 0, 0, 930, 5, "news.wapp.wii.com", "/", "http:", "", 1825 },
	--Redbox
	{ 0, 0, 0, 934, 22, "redbox.tt.omtrdc.net", "/", "http:", "", 1830 },
	--Mafiawars (Deprecated)
	--{ 0, 0, 0, 904, 22, "mafiawars.com", "/", "http:", "", 272 },
	--{ 0, 0, 0, 904, 22, "mafiawars.zynga.com", "/", "http:", "", 272 },
	--{ 0, 0, 0, 904, 22, "apps.facebook.com", "/inthemafia", "http:", "", 272 },
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
