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
detection_name: SSL Group Full "Primus"
version: 17
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Prezi' => 'Presentation tool.',
          'Atlassian' => 'Project Control and Management Software.',
          'Slate Magazine' => 'Online daily magazine.',
          'NBC' => 'Official website for NBC\'s Television network.',
          'Cabal Online' => 'Online multiplayer games.',
          'ALTools' => 'Software tools by ESTsoft.',
          'NHL.com' => 'The National Hockey League official website.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "ssl_host_group_full_Primus",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gSSLHostPatternList = {
	--NBC
	{ 0, 1988, 'nbcuniversalstore.com' },
	--{ 0, 1988, 'nbcuniversalstore.resultspage.com' },
	--Cabal Online
	{ 0, 1997, 'cabalonline.com' },
	--ALTools
	{ 0, 1998, 'altools.co.kr' },
	{ 0, 1998, 'altools.jp' },
	--Slate Magazine
	{ 0, 2000, 'slate.com' },
	--NHL.com
	{ 0, 2007, 'nhl.112.2o7.net' },
	{ 0, 2007, 'nhlstatic.com' },
	{ 0, 2007, 'nhl.bamcontent.com' },
	{ 0, 2007, 'nhl.bootstrap.fyre.co' },
	{ 0, 2007, 'nhlnetwork.viewerlink.tv' },
	--nrelate (Deprecated)
	--{ 0, 2022, 'nrelate.com' },
	--Atlassian
	{ 0, 2038, 'atlassian.net' },
	{ 0, 2038, 'hipchat.com' },
	--Prezi
	{ 0, 2040, 'prezi.com' },
}
function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3])
        end
    end
    return gDetector
end

function DetectorClean()
end
