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
detection_name: Payload Group "Primus"
version: 16
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Ubuntu' => 'Official website of Ubuntu.',
          'Brightcove' => 'Video hosting platform.',
          'Space.com' => 'Provides news related to Space and Astronomy.',
          'IFTTT' => 'Service to connect channels.',
          'Biography.com' => 'Stories, biographies about people.',
          'ALTools' => 'Software tools by ESTsoft.',
          'Apple iForgot' => 'Password reset portal for Apple.',
          'NBC' => 'Official website for NBC\'s Television network.',
          'GNOME' => 'Official website for GNOME, a desktop environment and graphical UI.',
          'Google Code project hosting' => 'Google site that hosts software projects.',
          'I Waste So Much Time' => 'Funny photos and videos around the world.',
          'BitGravity' => 'Content delivery network.',
          'RedOrbit' => 'Provides information about Science, Space, Technology and health related news.',
          'ESTsoft' => 'Provides software tools and online games.',
          'Adweek' => 'Marketing, Media and advertising news.',
          'Comedy Central' => 'Official website of Comedy Central, Television channel.',
          'NHL.com' => 'The National Hockey League official website.',
          'Prezi' => 'Presentation tool.',
          'Simpli.fi' => 'Ad portal.',
          'Wired.com' => 'Online magazine.',
          'Windows Help client' => 'Windows client for help and support services.',
          'E! Online' => 'Online entertainment news.',
          'Roku' => 'Device that streams internet video and audio to a TV.',
          'Atlassian' => 'Project Control and Management Software.',
          'TopTenREVIEWS' => 'Information, Reviews and recommendation about the product.',
          'Slate Magazine' => 'Online daily magazine.',
          'Cabal Online' => 'Online multiplayer games.',
          'The Week Magazine' => 'Online new magazine.',
          'Zmags' => 'Digital publisher for branded products to customer.',
          'Presto' => 'Printable emails and photos.',
          'Newser' => 'Online new portal.',
          'SockShare' => 'Provides online File sharing.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_Primus",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--NBC
	{ 0, 0, 0, 938, 22, "nbc.com", "/", "http:", "", 1988 },
	--RedOrbit
	{ 0, 0, 0, 939, 22, "redorbit.com", "/", "http:", "", 1989 },
	--Space.com
	{ 0, 0, 0, 940, 22, "space.com", "/", "http:", "", 1990 },
	--SockShare
	{ 0, 0, 0, 941, 9, "sockshare.com", "/", "http:", "", 1991 },
	--BitGravity
	{ 0, 0, 0, 942, 19, "bitgravity.com", "/", "http:", "", 1992 },
	--Zmags
	{ 0, 0, 0, 944, 22, "zmags.com", "/", "http:", "", 1994 },
	--GNOME
	{ 0, 0, 0, 945, 22, "gnome.org", "/", "http:", "", 1995 },
	--ESTsoft
	{ 0, 0, 0, 946, 22, "estsoft.com", "/", "http:", "", 1996 },
	--Cabal Online
	{ 0, 0, 0, 947, 20, "cabalonline.com", "/", "http:", "", 1997 },
	--ALTools
	{ 0, 0, 0, 948, 22, "altools.com", "/", "http:", "", 1998 },
	--Slate Magazine
	{ 0, 0, 0, 950, 33, "slate.com", "/", "http:", "", 2000 },
	--I Waste So Much Time
	{ 0, 0, 0, 951, 33, "iwastesomuchtime.com", "/", "http:", "", 2001 },
	--Biography.com
	{ 0, 0, 0, 952, 22, "biography.disqus.com", "/", "http:", "", 2002 },
	--Ubuntu
	{ 0, 0, 0, 953, 22, "ubuntu.com", "/", "http:", "", 2003 },
	--Comedy Central
	{ 0, 0, 0, 954, 22, "cc.com", "/", "http:", "", 2004 },
	--Wired.com
	{ 0, 0, 0, 955, 22, "wired.com", "/", "http:", "", 2005 },
	--E! Online
	{ 0, 0, 0, 956, 33, "eonline.com", "/", "http:", "", 2006 },
	--NHL.com
	{ 0, 0, 0, 957, 33, "nhl.112.2o7.net", "/", "http:", "", 2007 },
	--Presto
	{ 0, 0, 0, 958, 2, "presto.com", "/", "http:", "", 2008 },
	--TopTenREVIEWS
	{ 0, 0, 0, 964, 22, "toptenreviews.com", "/", "http:", "", 2016 },
	--Adweek
	{ 0, 0, 0, 965, 22, "adweek.com", "/", "http:", "", 2017 },
	--The Week Magazine
	{ 0, 0, 0, 966, 22, "theweek.com", "/", "http:", "", 2018 },
	--Brightcove
	{ 0, 0, 0, 967, 22, "brightcove.com", "/", "http:", "", 2019 },
	--Newser
	{ 0, 0, 0, 968, 22, "newser.com", "/", "http:", "", 2020 },
	--Simpli.fi
	{ 0, 0, 0, 969, 22, "simpli.fi", "/", "http:", "", 2021 },
	--Google Code project hosting
	{ 0, 0, 0, 971, 43, "googlecode.com", "/", "http:", "", 2032 },
	--Roku
	{ 0, 0, 0, 972, 38, "roku.com", "/", "http:", "", 2034 },
	--Atlassian
	{ 0, 0, 0, 973, 22, "atlassian.com", "/", "http:", "", 2038 },
	--Prezi
	{ 0, 0, 0, 974, 22, "prezi.com", "/", "http:", "", 2040 },
	--IFTTT
	{ 0, 0, 0, 975, 22, "ifttt.com", "/", "http:", "", 2041 },
	--Apple iForgot
	{ 0, 0, 0, 976, 22, "iforgot.apple.com", "/", "http:", "", 2045 },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance

    gDetector:addHttpPattern(2, 5, 0, 252, 24, 0, 0, 'HelpSupportServices', 2033)
    gDetector:addHttpPattern(2, 5, 0, 253, 19, 0, 0, 'Roku', 2034)

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10])
        end
    end

    return gDetector
end

function DetectorClean()
end
