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
detection_name: Payload Group "Femmes"
version: 17
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Technorati' => 'Search engine for blogs.',
          'ICQ2Go' => 'Web-based ICQ.',
          'Pinterest' => 'Social photo sharing website.',
          'TypePad' => 'Blogging service website.',
          'Google Product Search' => 'Google e-commerce site.',
          'The Pirate Bay' => 'BitTorrent index and search engine.',
          'Zynga Poker' => 'Poker game available on social network sites and mobile devices.',
          'Torrentz' => 'BitTorrent metasearch engine.',
          'Yahoo! Toolbar' => 'Yahoo!\'s browser toolbar.',
          'Docstor' => 'Electronic document storage site.',
          'MSDN' => 'Microsoft Developer Network.',
          'Mininova' => 'BitTorrent downloads website.',
          'PayPal' => 'E-commerce website for handling online transactions.',
          'CafeMom' => 'Social networking site targeted towards mothers.',
          'MetaCrawler' => 'Metasearch engine that combines results from various popular search engines.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_femmes",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--CafeMom
	{ 0, 0, 0, 427, 5, "cafemom.com", "/", "http:", "", 1129 },
	--MetaCrawler
	{ 0, 0, 0, 430, 22, "metacrawler.com", "/", "http:", "", 1132 },
	--Mininova
	{ 0, 0, 0, 431, 9, "mininova.org", "/", "http:", "", 1133 },
	--PayPal
	{ 0, 0, 0, 432, 15, "paypal.com", "/", "http:", "", 1134 },
	--Pinterest
	{ 0, 0, 0, 433, 5, "pinterest.com", "/", "http:", "", 1135 },
	--The Pirate Bay
	{ 0, 0, 0, 434, 9, "thepiratebay.org", "/", "http:", "", 1136 },
	--Technorati
	{ 0, 0, 0, 435, 22, "technorati.com", "/", "http:", "", 1137 },
	--Torrentz
	{ 0, 0, 0, 436, 9, "torrentz.com", "/", "http:", "", 1138 },
	--TypePad
	{ 0, 0, 0, 437, 5, "typepad.com", "/", "http:", "", 1139 },
	--ICQ2Go
	{ 0, 0, 0, 42, 10, "api.oscar.aol.com", "/", "http:", "", 222 },
	--MSDN
	{ 0, 0, 0, 423, 15, "msdn.microsoft.com", "/", "http:", "", 304 },
	--Google Product Search
	{ 0, 0, 0, 151, 15, "google.com", "/prdhp", "http:", "", 664 },
	--Docstor
	{ 0, 0, 0, 425, 9, "docstor.com", "/", "http:", "", 898 },
	--Zynga Poker
	{ 0, 0, 0, 422, 20, "poker.zynga.com", "/", "http:", "", 910 },
	--Yahoo! Toolbar
	{ 0, 0, 0, 20, 7, "toolbar.yahoo.com", "/", "http:", "", 947 },
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
