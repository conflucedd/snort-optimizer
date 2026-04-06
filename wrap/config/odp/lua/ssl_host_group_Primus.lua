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
detection_name: SSL Group "Primus"
version: 16
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Space.com' => 'Provides news related to Space and Astronomy.',
          'Apple iForgot' => 'Password reset portal for Apple.',
          'NBC' => 'Official website for NBC\'s Television network.',
          'GNOME' => 'Official website for GNOME, a desktop environment and graphical UI.',
          'Simpli.fi' => 'Ad portal.',
          'NHL.com' => 'The National Hockey League official website.',
          'SockShare' => 'Provides online File sharing.',
          'Ubuntu' => 'Official website of Ubuntu.',
          'Zmags' => 'Digital publisher for branded products to customer.',
          'IFTTT' => 'Service to connect channels.',
          'Wired.com' => 'Online magazine.',
          'ALTools' => 'Software tools by ESTsoft.',
          'Slate Magazine' => 'Online daily magazine.',
          'Atlassian' => 'Project Control and Management Software.',
          'ESTsoft' => 'Provides software tools and online games.',
          'Presto' => 'Printable emails and photos.',
          'Prezi' => 'Presentation tool.',
          'BitGravity' => 'Content delivery network.',
          'Brightcove' => 'Video hosting platform.',
          'Cabal Online' => 'Online multiplayer games.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "ssl_host_group_Primus",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gSSLHostPatternList = {
	--NBC
	{ 0, 1988, 'nbc.com' },
	--Space.com
	{ 0, 1990, 'hermanstreet.com' },
	--SockShare
	{ 0, 1991, 'sockshare.com' },
	--BitGravity
	{ 0, 1992, 'bitgravity.com' },
	--Zmags
	{ 0, 1994, 'zmags.com' },
	--GNOME
	{ 0, 1995, 'gnome.org' },
	--ESTsoft
	{ 0, 1996, 'estgames.com' },
	--Cabal Online
	{ 0, 1997, 'cabal.com' },
	--ALTools
	{ 0, 1998, 'altools.com' },
	--Slate Magazine
	{ 0, 2000, 'slate-id-prod.s3.amazonaws.com' },
	--Ubuntu
	{ 0, 2003, 'ubuntu.com' },
	--Wired.com
	{ 0, 2005, 'wired.com' },
	--NHL.com
	{ 0, 2007, 'nhl.com' },
	--Presto
	{ 0, 2008, 'presto.com' },
	--Brightcove
	{ 0, 2019, 'brightcove.com' },
	--Simpli.fi
	{ 0, 2021, 'simpli.fi' },
	--Atlassian
	{ 0, 2038, 'atlassian.com' },
	--Prezi
	{ 0, 2040, 'prezi-a.akamaihd.net' },
	--IFTTT
	{ 0, 2041, 'ifttt.com' },
	--Apple iForgot
	{ 0, 2045, 'iforgot.apple.com' },
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
