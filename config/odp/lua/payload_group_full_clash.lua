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
detection_name: Payload Group Full "Clash"
version: 31
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Nordstrom' => 'Retail department store.',
          'Google Drive' => 'A free office suite and cloud storage system hosted by Google.',
          'Vimeo' => 'Website for viewing and sharing videos.',
          'Tiffany & Co.' => 'Jewelry and silverware retailer.',
          'ImageShack' => 'Image hosting website.',
          'ShopStyle' => 'Fashion search engine which links to various retailers.',
          'ShowDocument' => 'Web application that allows users to collaborate on and review documents in real time.',
          'Box' => 'File storage and transfer site.',
          'Flickr' => 'An image hosting and video hosting website, web services suite, and online community.',
          'Delicious' => 'Social bookmarking website for storing, sharing, and finding web bookmarks.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "payload_group_full_clash",
    proto =  DC.ipproto.tcp,
    client = {
        init = 'DetectorInit',
        clean = 'DetectorClean',
        minimum_matches = 1
    }
}

gUrlPatternList = {
	--Box
	{ 0, 0, 0, 217, 9, "box.com", "/", "http:", "", 1326 },
	{ 0, 0, 0, 217, 9, "box.org", "/", "http:", "", 1326 },
	{ 0, 0, 0, 217, 9, "boxcdn.net", "/", "http:", "", 1326 },
	{ 0, 0, 0, 217, 9, "boxcloud.com", "/", "http:", "", 1326 },
	{ 0, 0, 0, 217, 9, "boxrelay.com", "/", "http:", "", 1326 },
	--Flickr
	{ 0, 0, 0, 225, 5, "static.flickr.com", "/", "http:", "", 159 },
	--Google Drive
	{ 0, 0, 0, 285, 11, "drive.google.com", "/", "http:", "", 180 },
	{ 0, 0, 0, 285, 11, "drive-thirdparty.googleusercontent.com", "/", "http:", "", 180 },
	{ 0, 0, 0, 285, 11, "googledrive.com", "/", "http:", "", 180 },
	{ 0, 0, 0, 285, 11, "google.com", "/drive", "http:", "", 180 },
	{ 0, 0, 0, 285, 11, "upload.video.google.com", "/", "http:", "", 180 },
	--Hotfile (Deprecated)
	--{ 0, 0, 0, 232, 9, "hotfile.com", "/", "http:", "", 204 },
	--beWeeVee (Deprecated)
	--{ 0, 0, 0, 283, 8, "beweevee.com", "/", "http:", "", 568 },
	--Delicious
	{ 0, 0, 0, 221, 14, "icio.us", "/", "http:", "", 605 },
	--ILoveIM (Deprecated)
	--{ 0, 0, 0, 234, 10, "iloveim.com", "/", "http:", "", 681 },
	--ImageShack
	{ 0, 0, 0, 235, 9, "imageshack.com", "/", "http:", "", 682 },
	--Megavideo (Deprecated)
	--{ 0, 0, 0, 244, 13, "megavideo.com", "/", "http:", "", 726 },
	--Minus (Deprecated)
	--{ 0, 0, 0, 247, 9, "minus.com", "/", "http:", "", 733 },
	--{ 0, 0, 0, 247, 9, "min.us", "/", "http:", "", 733 },
	--Nordstrom
	{ 0, 0, 0, 252, 45, "nordstromimage.com", "/", "http:", "", 764 },
	--ShopStyle
	{ 0, 0, 0, 265, 32, "shopstyle.fr", "/", "http:", "", 828 },
	{ 0, 0, 0, 265, 32, "shopstyle.de", "/", "http:", "", 828 },
	--ShowDocument
	{ 0, 0, 0, 284, 8, "showdocument.net", "/", "http:", "", 831 },
	--Tiffany & Co.
	{ 0, 0, 0, 271, 26, "tiffany.co", "/", "http:", "", 870 },
	{ 0, 0, 0, 271, 26, "tiffany.ca", "/", "http:", "", 870 },
	{ 0, 0, 0, 271, 26, "tiffany.cn", "/", "http:", "", 870 },
	{ 0, 0, 0, 271, 26, "tiffany.kr", "/", "http:", "", 870 },
	{ 0, 0, 0, 271, 26, "tiffany.at", "/", "http:", "", 870 },
	{ 0, 0, 0, 271, 26, "tiffany.fr", "/", "http:", "", 870 },
	{ 0, 0, 0, 271, 26, "tiffany.de", "/", "http:", "", 870 },
	{ 0, 0, 0, 271, 26, "tiffany.it", "/", "http:", "", 870 },
	{ 0, 0, 0, 271, 26, "tiffany.es", "/", "http:", "", 870 },
	--Vimeo
	{ 0, 0, 0, 277, 13, "vimeocdn.com", "/", "http:", "", 893 },
	--Zooomr (Deprecated)
	--{ 0, 0, 0, 282, 9, "zooomr.com", "/", "http:", "", 933 },
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
