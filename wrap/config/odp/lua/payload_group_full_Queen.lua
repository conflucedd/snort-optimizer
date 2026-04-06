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
detection_name: Payload Group Full "Queen"
version: 26
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Youtube Upload' => 'Upload and share videos.',
          'Game Center' => 'Social gaming app for iOS.',
          'FOX' => 'Official website for Fox entertainment.',
          'GOLF.com' => 'News, instruction and courses about Golf.',
          'Yahoo!' => 'Yahoo! and it\'s online services.',
          'CBS' => 'CBS news website.',
          'C-SPAN' => 'Cable-Satellite Public Affairs Network - Non-profit cable television.',
          'DSW' => 'Designer Shoe Warehouse - branded footwear.',
          'Entertainment Weekly' => 'Entertainment new and video clips.',
          'Speedtest' => 'Test the download and upload speed of the internet.',
          'Clear Channel' => 'Aggregates online radio broadcasting.',
          'Woopra' => 'Real time customer service and solutions.',
          'Audible.com' => 'Digital audio version for books, magazines, information and other entertainments.',
          'Adobe Software' => 'Adobe software and updates.',
          'Flickr Upload' => 'Online photo management and sharing.',
          'FreeStreams' => 'Online Movies, Radio and Games.',
          'FriendFinder' => 'Online friend finder and dating site.',
          'OCLC' => 'Online Computer Library Center - Nonprofit collaboration for providing online public access catalog.',
          'Scribd Upload' => 'Sharing, publishing, discussing and discovering documents. This app can be detected from decrypted traffic only.',
          'Microsoft Azure' => 'Cloud computing by Microsoft.',
          'NCAA' => 'National Collegiate Athletic Association - non-profit association for athletic programs.',
          'OpenBSD' => 'Open source code for security, enterprise and server.',
          'OpenSUSE' => 'Official website for OpenSUSE, Linux based OS.',
          'Washington Times' => 'Official web site for the Washington times news portal.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_full_Queen",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--CBS
	{ 0, 0, 0, 980, 22, "cbsstatic.com", "/", "http:", "", 1332 },
	{ 0, 0, 0, 980, 22, "cbslocal.com", "/", "http:", "", 1332 },
	--FOX
	{ 0, 0, 0, 981, 22, "foxnetworks.tt.omtrdc.net", "/", "http:", "", 2050 },
	{ 0, 0, 0, 981, 22, "foxnet.demdex.net", "/", "http:", "", 2050 },
	{ 0, 0, 0, 981, 22, "fbchdvod-f.akamaihd.net", "/z/Fox.com", "http:", "", 2050 },
	--Washington Times
	{ 0, 0, 0, 982, 33, "washtimes.com", "/", "http:", "", 2051 },
	{ 0, 0, 0, 982, 33, "washtimes.disqus.com", "/", "http:", "", 2051 },
	{ 0, 0, 0, 982, 33, "chartbeat.net", "/", "http:", "washingtontimes", 2051 },
	--OpenBSD
	{ 0, 0, 0, 984, 22, "openbsd.org", "/", "http:", "", 2053 },
	--OpenSUSE
	{ 0, 0, 0, 987, 22, "opensuse.com", "/", "http:", "", 2056 },
	--NCAA
	{ 0, 0, 0, 989, 22, "ncaa.org", "/", "http:", "", 2058 },
	{ 0, 0, 0, 989, 22, "turner.com", "/NCAA/", "http:", "", 2058 },
	--DSW
	{ 0, 0, 0, 991, 22, "dsw.112.2o7.net", "/", "http:", "", 2059 },
	{ 0, 0, 0, 991, 22, "scene7.com", "/DSWShoes/", "http:", "", 2059 },
	--FreeStreams
	{ 0, 0, 0, 995, 22, "freestreams.eu", "/", "http:", "", 2063 },
	--Clear Channel
	{ 0, 0, 0, 996, 22, "clearchannelinternational.com", "/", "http:", "", 2064 },
	--GOLF.com
	{ 0, 0, 0, 997, 22, "cdn.turner.com", "/dr/golf", "http:", "", 2065 },
	--Woopra
	{ 0, 0, 0, 1001, 22, "disqus.com", "/woopra/", "http:", "", 2069 },
	--OCLC
	{ 0, 0, 0, 1002, 22, "oclc.com", "/", "http:", "", 2070 },
	--C-SPAN
	{ 0, 0, 0, 1005, 22, "c-spanvideo.org", "/", "http:", "", 2074 },
	{ 0, 0, 0, 1005, 22, "c-spanarchives.org", "/", "http:", "", 2074 },
	--Game Center
	{ 0, 0, 0, 1012, 20, "developer.apple.com/game-center", "/", "http:", "", 2092 },
	--FriendFinder
	{ 0, 0, 0, 1013, 22, "pop6.com", "/", "http:", "", 2093 },
	--Audible.com
	{ 0, 0, 0, 1014, 22, "audible.tt.omtrdc.net", "/", "http:", "", 2094 },
	--Entertainment Weekly
	{ 0, 0, 0, 1015, 22, "timeinc.net", "/ew/", "http:", "", 2095 },
	--Docstoc Upload (Deprecated)
	--{ 0, 0, 0, 1016, 22, "docstoc.com", "/upload", "http:", "", 2102 },
	--{ 0, 0, 0, 1016, 22, "docstoccdn.com", "/upload", "http:", "", 2102 },
	--Speedtest
	{ 0, 0, 0, 1017, 22, "speedtest.consolidated.net", "/", "http:", "", 2103 },
	--Flickr Upload
	{ 0, 0, 0, 1019, 22, "flickr.com", "/upload", "http:", "", 2105 },
	{ 0, 0, 0, 1019, 22, "flickr.com", "/beacon_uploadr_timings", "http:", "", 2105 },
	{ 0, 0, 0, 1019, 22, "up.flickr.com", "/services/upload/", "http:", "", 2105 },
	{ 0, 0, 0, 1019, 22, "flickr.com", "/photos/upload/", "http:", "", 2105 },
	--Scribd Upload
	{ 0, 0, 0, 1020, 22, "scribd.com", "/newuploads", "http:", "", 2106 },
	{ 0, 0, 0, 1020, 22, "scribd.com", "/upload-document", "http:", "", 2106 },
	--Youtube Upload
	{ 0, 0, 0, 1021, 22, "ytimg.com", "/yts/img/upload", "http:", "", 2107 },
	{ 0, 0, 0, 1021, 22, "upload.youtube.com", "/", "http:", "", 2107 },
	--Microsoft Azure
	{ 0, 0, 0, 1025, 22, "thewindowsazureproductsite.disqus.com", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "msecnd.net", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "windows.net", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "microsoftonline-p.com", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "microsoftonline-p.net", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "microsoftonlineimages.com", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "msocdn.com", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "activedirectory.windowsazure.com", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "phonefactor.net", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "aadrm.com", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "azurerms.com", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "cloudapp.net", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "liverdcxstorage.blob.core.windowsazure.com", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "telemetry.remoteapp.windowsazure.com", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "www.remoteapp.windowsazure.com", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "blob.core.windows.net", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "servicebus.windows.net", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "adhybridhealth.azure.com", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "table.core.windows.net", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "policykeyservice.dc.ad.msft.net", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "secure.aadcdn.microsoftonline-p.com", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "azure.com", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "azure.microsoft.com", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "azurecomcdn.net", "/", "http:", "", 2111 },
	{ 0, 0, 0, 1025, 22, "keydelivery.mediaservices.windows.net", "/", "http:", "", 2111 },
	--Yahoo!
	{ 0, 0, 0, 990, 22, "yimg.com", "/", "http:", "", 524 },
	--Adobe Software
	{ 0, 0, 0, 21, 22, "adobe.com", "/", "http:", "", 541 },
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
