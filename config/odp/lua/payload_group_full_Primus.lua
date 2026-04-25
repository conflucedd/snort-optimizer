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
detection_name: Payload Group Full "Primus"
version: 17
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'NHL.com' => 'The National Hockey League official website.',
          'ALTools' => 'Software tools by ESTsoft.',
          'The Week Magazine' => 'Online new magazine.',
          'Wired.com' => 'Online magazine.',
          'Slate Magazine' => 'Online daily magazine.',
          'Comedy Central' => 'Official website of Comedy Central, Television channel.',
          'I Waste So Much Time' => 'Funny photos and videos around the world.',
          'NBC' => 'Official website for NBC\'s Television network.',
          'Cabal Online' => 'Online multiplayer games.',
          'Atlassian' => 'Project Control and Management Software.',
          'Space.com' => 'Provides news related to Space and Astronomy.',
          'Biography.com' => 'Stories, biographies about people.',
          'Adweek' => 'Marketing, Media and advertising news.',
          'Prezi' => 'Presentation tool.',
          'ESTsoft' => 'Provides software tools and online games.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_full_Primus",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--NBC
	{ 0, 0, 0, 938, 22, "nbcuni.com", "/", "http:", "", 1988 },
	{ 0, 0, 0, 938, 22, "nbcuniversalstore.com", "/", "http:", "", 1988 },
	{ 0, 0, 0, 938, 22, "nbcustr.netmng.com", "/", "http:", "", 1988 },
	{ 0, 0, 0, 938, 22, "nbcudigitaladops.com", "/", "http:", "", 1988 },
	{ 0, 0, 0, 938, 22, "nbcdotcom-f.akamaihd.net", "/", "http:", "", 1988 },
	{ 0, 0, 0, 938, 22, "nbcvod-i.akamaihd.net", "/", "http:", "", 1988 },
	--{ 0, 0, 0, 938, 22, "nbcuniversalstore.resultspage.com", "/", "http:", "", 1988 },
	--Space.com
	{ 0, 0, 0, 940, 22, "hermanstreet.com", "/", "http:", "", 1990 },
	--Zmags
	--{ 0, 0, 0, 944, 22, "zmags.app4.hubspot.com", "/", "http:", "", 1994 },
	--ESTsoft
	{ 0, 0, 0, 946, 22, "estgames.com", "/", "http:", "", 1996 },
	--Cabal Online
	{ 0, 0, 0, 947, 20, "cabal.com", "/", "http:", "", 1997 },
	{ 0, 0, 0, 947, 20, "cabal.estgames.com", "/", "http:", "", 1997 },
	{ 0, 0, 0, 947, 20, "cabalsea.com", "/", "http:", "", 1997 },
	{ 0, 0, 0, 947, 20, "cabal.e-games.com.ph", "/", "http:", "", 1997 },
	--{ 0, 0, 0, 947, 20, "cabal.zzima.com", "/", "http:", "", 1997 },
	--ALTools
	{ 0, 0, 0, 948, 22, "altools.co.kr", "/", "http:", "", 1998 },
	{ 0, 0, 0, 948, 22, "altools.jp", "/", "http:", "", 1998 },
	--Slate Magazine
	{ 0, 0, 0, 950, 33, "slatev.com", "/", "http:", "", 2000 },
	--I Waste So Much Time
	{ 0, 0, 0, 951, 33, "iwsmt.disqus.com", "/", "http:", "", 2001 },
	{ 0, 0, 0, 951, 33, "dropdash.com", "/", "http:", "iwsmt", 2001 },
	--Biography.com
	{ 0, 0, 0, 952, 22, "biography.com", "/", "http:", "", 2002 },
	{ 0, 0, 0, 952, 22, "shop.history.com", "/", "http:", "biography", 2002 },
	--Comedy Central
	{ 0, 0, 0, 954, 22, "comedycentral.com", "/", "http:", "", 2004 },
	{ 0, 0, 0, 954, 22, "thedailyshow.com", "/", "http:", "", 2004 },
	{ 0, 0, 0, 954, 22, "colbertnation.com", "/", "http:", "", 2004 },
	{ 0, 0, 0, 954, 22, "jokes.com", "/", "http:", "", 2004 },
	{ 0, 0, 0, 954, 22, "viacomedycentral.112.2o7.net", "/", "http:", "", 2004 },
	{ 0, 0, 0, 954, 22, "mtvn.112.2o7.net", "/", "http:", "comedycentral", 2004 },
	{ 0, 0, 0, 954, 22, "mtvnservices.com", "/", "http:", "comedycentral", 2004 },
	{ 0, 0, 0, 954, 22, "jokes.mtvnimages.com", "/", "http:", "", 2004 },
	{ 0, 0, 0, 954, 22, "thedailyshow.mtvnimages.com", "/", "http:", "", 2004 },
	{ 0, 0, 0, 954, 22, "colbertnation.mtvnimages.com", "/", "http:", "", 2004 },
	{ 0, 0, 0, 954, 22, "comedycentrl.com", "/", "http:", "", 2004 },
	--Wired.com
	{ 0, 0, 0, 955, 22, "wiredopinion.disqus.com", "/", "http:", "", 2005 },
	{ 0, 0, 0, 955, 22, "wiredinsider.com", "/", "http:", "", 2005 },
	{ 0, 0, 0, 955, 22, "wiredinsider.tumblr.com", "/", "http:", "", 2005 },
	--NHL.com
	{ 0, 0, 0, 957, 33, "nhl.com", "/", "http:", "", 2007 },
	{ 0, 0, 0, 957, 33, "nhle.com", "/", "http:", "", 2007 },
	{ 0, 0, 0, 957, 33, "nhl.bamcontent.com", "/", "http:", "", 2007 },
	{ 0, 0, 0, 957, 33, "findnhlnetwork.com", "/", "http:", "", 2007 },
	--{ 0, 0, 0, 957, 33, "nhl.cdnllnwnl.neulion.net", "/", "http:", "", 2007 },
	--Adweek
	{ 0, 0, 0, 965, 22, "adweekmedia.disqus.com", "/", "http:", "", 2017 },
	--The Week Magazine
	{ 0, 0, 0, 966, 22, "theweekus.disqus.com", "/", "http:", "", 2018 },
	{ 0, 0, 0, 966, 22, "nrelate.com", "/", "http:", "theweek.com", 2018 },
	--nrelate (Deprecated)
	--{ 0, 0, 0, 970, 22, "nrelate.com", "/", "http:", "", 2022 },
	--Atlassian
	{ 0, 0, 0, 973, 22, "hipchat.com", "/", "http:", "", 2038 },
	--Prezi
	{ 0, 0, 0, 974, 22, "prezi-a.akamaihd.net", "/", "http:", "", 2040 },
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
