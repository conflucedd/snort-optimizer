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
detection_name: SSL Group Full "backstreetboys"
version: 23
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Freelancer' => 'Site for job listings for temporary work.',
          'Wordpress' => 'An online blogging community.',
          'Groupon' => 'Gift certificate website.',
          'Freewheel' => 'Advertisement site.',
          'VPNReactor' => 'An anonymizer that obfuscates web usage.',
          'Webtrends' => 'Advertisement site.',
          'Webs' => 'Photo, video, and file sharing, and online marketplace.',
          'wikidot' => 'Site that provides wikis.',
          'Channel 4' => 'British based streaming television.',
          'Ligatus' => 'Advertising and analytics site.',
          'Weborama' => 'Video ad site.',
          'Zoho' => 'A Web- based online office suite containing word processing, spreadsheets, presentations, databases, note-taking, wikis, CRM, project management, invoicing and other applications developed by ZOHO Corporation.',
          'Zanox' => 'Advertising and analytics site.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "ssl_host_group_full_backstreetboys",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gSSLHostPatternList = {
	--Webs
	{ 0, 1228, 'freewebs.com' },
	{ 0, 1228, 'websimages.com' },
	--wikidot
	{ 0, 2352, 'wdfiles.com' },
	--Foursquare
	--{ 0, 2357, '4sqi.net' },
	--Groupon
	{ 0, 2361, 'grouponcdn.com' },
	--Freelancer
	{ 0, 2483, 'freelancer.com' },
	{ 0, 2483, 'freelancer.cl' },
	{ 0, 2483, 'freelancer.co.id' },
	{ 0, 2483, 'freelancer.co.nz' },
	{ 0, 2483, 'freelancer.co.za' },
	{ 0, 2483, 'freelancer.com.au' },
	{ 0, 2483, 'freelancer.com.bd' },
	{ 0, 2483, 'freelancer.com.es' },
	{ 0, 2483, 'freelancer.com.jm' },
	{ 0, 2483, 'freelancer.com.pe' },
	{ 0, 2483, 'freelancer.de' },
	{ 0, 2483, 'freelancer.ec' },
	{ 0, 2483, 'f-cdn.com' },
	--TLVMedia
	--{ 0, 2536, 'tlvmedia.com' },
	--Ybrant Digital
	--{ 0, 2546, 'lycos.com' },
	--eNovance (Deprecated)
	--{ 0, 2567, 'enovance.com' },
	--Freewheel
	{ 0, 2574, 'freewheel.com' },
	--Webtrends
	{ 0, 2587, 'webtrendslive.com' },
	--VPNReactor
	{ 0, 3652, 'vpnreactor.com' },
	--Ligatus
	{ 0, 3712, 'ligatus.at' },
	{ 0, 3712, 'ligatus.es' },
	{ 0, 3712, 'ligatus.be' },
	{ 0, 3712, 'ligatus.nl' },
	{ 0, 3712, 'ligatus.it' },
	{ 0, 3712, 'ligatus.fr' },
	--{ 0, 3712, 'ligatus.ch' },
	--{ 0, 3712, 'ligatus.de' },
	--Weborama
	{ 0, 3723, 'weborama.com' },
	--Zanox
	{ 0, 3725, 'zanox.softgarden.io' },
	--Channel 4
	{ 0, 3811, 'channel4.com' },
	--Wordpress
	{ 0, 506, 'wp.com' },
	--Zoho
	{ 0, 528, 'zohostatic.com' },
	{ 0, 528, 'zohospotlight.com' },
	{ 0, 528, 'zohopublic.com' },
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
