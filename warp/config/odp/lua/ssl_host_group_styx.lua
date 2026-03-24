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
detection_name: SSL Group "Styx"
version: 9
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Zapier' => 'Automatically sync the web apps.',
          'Fifth Third Bank' => 'A bank.',
          'Campfire' => 'Business-focused group messaging and enterprise social networking.',
          'Sony' => 'Official website for Sony Corporation.',
          'WeTransfer' => 'Online file transferring platform.',
          'Flickr' => 'An image hosting and video hosting website, web services suite, and online community.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_styx",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gSSLHostPatternList = {

    -- Zapier
    { 0, 2206, 'zapier.com' },
    -- Sony
    { 0, 2234, 'sony.com' },
    { 0, 2234, 'sony.lu' },
    { 0, 2234, 'sony.co.cr' },
    { 0, 2234, 'sony.co.in' },
    { 0, 2234, 'sony.fi' },
    { 0, 2234, 'sony.no' },
    { 0, 2234, 'sony.be' },
    { 0, 2234, 'sony.se' },
    { 0, 2234, 'sony.it' },
    { 0, 2234, 'sony.eu' },
    { 0, 2234, 'sony.ci' },
    { 0, 2234, 'sony.hu' },
    { 0, 2234, 'sony.ch' },
    { 0, 2234, 'sony.cl' },
    { 0, 2234, 'sony.fr' },
    { 0, 2234, 'sony.nl' },
    { 0, 2234, 'sony.ee' },
    { 0, 2234, 'sony.net' },
    { 0, 2234, 'sony.es' },
    { 0, 2234, 'sony.ua' },
    { 0, 2234, 'sony.pl' },
    { 0, 2234, 'sony.co.id' },
    { 0, 2234, 'sony.ca' },
    { 0, 2234, 'sony.hr' },
    { 0, 2234, 'sony.ba' },
    { 0, 2234, 'sony.rs' },
    { 0, 2234, 'sony.co.kr' },
    { 0, 2234, 'sony.co.nz' },
    { 0, 2234, 'sony.kz' },
    { 0, 2234, 'sony.ro' },
    { 0, 2234, 'sony.gr' },
    { 0, 2234, 'sony.ru' },
    { 0, 2234, 'sony.si' },
    { 0, 2234, 'sony.ie' },
    { 0, 2234, 'sony.co.th' },
    { 0, 2234, 'sony.lv' },
    { 0, 2234, 'sony.cz' },
    { 0, 2234, 'sony.de' },
    { 0, 2234, 'sony.sk' },
    { 0, 2234, 'sony.dk' },
    { 0, 2234, 'sony.bg' },
    -- Zootool
    -- { 0, 2235, 'zootool.com' },
    -- WeTransfer
    { 0, 2236, 'wetransfer.com' },
    -- Postini
    --{ 0, 2244, 'login.postini.com' },
    -- Fifth Third Bank
    { 0, 2257, '53.com' },
    -- Flickr
    { 0, 159, 'flickr.com'},
    -- Campfire
    { 0, 2270, 'campfirenow.com'},
    -- App.net
    --{ 0, 2286, 'app.net'},
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end
    return gDetector;
end

function DetectorClean()
end

