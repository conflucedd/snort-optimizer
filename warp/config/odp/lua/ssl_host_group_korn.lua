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
detection_name: SSL Group "korn"
version: 14
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'Hotstar' => 'Video streaming app for Star India.',
          'RealVNC' => 'A VNC package that supports client and server side, and also provides cloud-based services such as chat and file transfer.',
          'AnyDesk' => 'Remote Desktop Access Software.',
          'ZenVPN' => 'VPN/anonymizer app.',
          'Elephant Drive' => 'Cloud storage service used primarily as an online backup tool.',
          'Showbox' => 'Mobile application providing streaming video content.',
          'NetSarang' => 'Network connectivity and management tools package.',
          'Open Drive' => 'Cloud storage and online backup system.',
          'Flightradar24' => 'Real-time aircraft flight tracking web service.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_korn",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

--detectorType(0-> Web, 1->Client),  AppId, SSLPattern
gSSLHostPatternList = {

    --RealVNC
    { 1, 4142, 'services.vnc.com'},
    --Elephant Drive
    { 0, 4143, 'elephantdrive.com'},
    { 0, 4143, 'seal.starfieldtech.com'},
    { 0, 4143, 'bucket1-direct-elephantdrive-com.s3.amazonaws.com'},
    --Open Drive
    { 0, 4144, 'od.lk'},
    { 0, 4144, 'opendrive.com'},
    --AnyDesk
    { 0, 4145, 'anydesk.com'},
    { 0, 4145, 'anydesk.de'},
    { 0, 4145, 'anydesk.it'},
    { 0, 4145, 'anydesk.fr'},
    { 0, 4145, 'anydesk.dk'},
    { 0, 4145, 'anydesk.pl'},
    { 0, 4145, 'anydesk.cz'},
    { 0, 4145, 'anydesk.pt'},
    { 0, 4145, 'anydesk.es'},
    { 0, 4145, 'anydesk.se'},
    { 0, 4145, 'anydesk.sk'},
    { 0, 4145, 'anydesk.gr'},
    --NetSarang
    { 0, 4146, 'netsarang.com'},
    --Flightradar24
    { 0, 4148, 'flightradar24.com'},
    --Showbox
    { 0, 4149, 'showboxforipad.com'},
    { 0, 4149, 'showboxapkp.com'},
    { 0, 4149, 'showboxdownload.com'},
    { 0, 4149, 'showboxa.com'},
    { 0, 4149, 'showboxdownload.site'},
    { 0, 4149, 'showboxapkdownload.org'},
    { 0, 4149, 'showbox.kim'},
    --ZenVPN
    { 1, 4150, 'zenvpn.net'},
    --Hotstar
    { 0, 4153, 'hotstar.com'},
    { 1, 4153, 'staragvod3-vh.akamaihd.net'},
    { 1, 4153, 'hotstar-sin.gravityrd-services.com'},
    { 0, 4153, 'media0-starag.startv.in' },                                                         
    { 0, 4153, 'media1-starag.startv.in' },                                                         
    { 0, 4153, 'media2-starag.startv.in' },
    { 0, 4153, 'starsports.com' },
}

gSSLCnamePatternList = {

    --AnyDesk
    { 1, 4145, 'AnyNet Relay' },
    { 1, 4145, 'AnyNet Root CA' },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSLCertPattern then
        for i,v in ipairs(gSSLHostPatternList) do
            gDetector:addSSLCertPattern(v[1],v[2],v[3]);
        end
    end

    if gDetector.addSSLCnamePattern then
        for i,v in ipairs(gSSLCnamePatternList) do
            gDetector:addSSLCnamePattern(v[1],v[2],v[3]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

