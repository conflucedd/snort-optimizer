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
detection_name: SSL Group Full "Queen"
version: 14
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Audible.com' => 'Digital audio version for books, magazines, information and other entertainments.',
          'Windows Live SkyDrive' => 'Cloud based file hosting service.',
          'Microsoft Azure' => 'Cloud computing by Microsoft.',
          'DSW' => 'Designer Shoe Warehouse - branded footwear.',
          'Game Center' => 'Social gaming app for iOS.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "ssl_host_group_full_Queen",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gSSLHostPatternList = {
	--DSW
	{ 0, 2059, 'dsw.tt.omtrdc.net' },
	--Game Center
	{ 1, 2092, 'service.gc.apple.com' },
	--Audible.com
	{ 0, 2094, 'audible.112.2o7.net' },
	{ 0, 2094, 'audible.tt.omtrdc.net' },
	--Microsoft Azure
	{ 0, 2111, 'windows.net' },
	{ 0, 2111, 'azurecomcdn.net' },
	{ 0, 2111, 'azure.microsoft.com' },
	{ 0, 2111, 'azure.com' },
	{ 0, 2111, 'azure.net' },
	{ 0, 2111, 'msecnd.net' },
	{ 0, 2111, 'microsoftonline-p.com' },
	{ 0, 2111, 'microsoftonline-p.net' },
	{ 0, 2111, 'microsoftonlineimages.com' },
	{ 0, 2111, 'msocdn.com' },
	{ 0, 2111, 'phonefactor.net' },
	{ 0, 2111, 'aadrm.com' },
	{ 0, 2111, 'azurerms.com' },
	{ 0, 2111, 'cloudapp.net' },
	{ 0, 2111, 'policykeyservice.dc.ad.msft.net' },
	{ 0, 2111, 'microsoftazuread-sso.com' },
	--Windows Live SkyDrive
	{ 0, 911, 'skydrivesync,policies.live.net' },
	{ 0, 911, 'live.filestore.com' },
	--{ 0, 911, 'storage.live.com' },
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
