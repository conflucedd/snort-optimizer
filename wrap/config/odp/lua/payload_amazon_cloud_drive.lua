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
detection_name: Amazon Cloud Drive
version: 2
description: Web Storage application.
bundle_description: $VAR1 = {
          'Amazon Cloud Drive' => 'Web Storage application.',
          'Amazon Cloud Drive Download' => 'Download action from Amazon cloud drive, a web Storage application.',
          'Amazon Cloud Drive Upload' => 'Upload action from Amazon cloud drive, a web Storage application.',
          'Amazon Cloud Drive Authenticate' => 'Login action from Amazon cloud drive, a web Storage application.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "Amazon Cloud Drive",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        validate =  'DetectorValidator',
        minimum_matches =  1
    }
}

--serviceId, clientId, ClientType, PayloadId, PayloadType, hostPattern, pathPattern, schemePattern, queryPattern
gUrlPatternList = {

    --  Amazon Cloud Drive
    { 0, 0, 0, 1958, 1, "amazon.com", "/clouddrive", "http:", "", 3640 },
    { 0, 0, 0, 1958, 1, "drive.amazonaws.com", "/cdproxy", "http:", "", 3640 },
    { 0, 0, 0, 1958, 1, "amazon.com", "/1/batch", "http:", "", 3640 },

     --  Amazon Cloud Drive Download
    { 0, 0, 0, 1959, 1, "drive.amazonaws.com", "/v2/download", "http:", "", 3641 },

    --  Amazon Cloud Drive Upload
    { 0, 0, 0, 1960, 1, "drive.amazonaws.com", "/cdproxy/drive/v1/nodes", "http:", "", 3642 },
}

function DetectorClean()
end

function DetectorInit(detectorInstance)
    gDetector = detectorInstance
    if (gDetector.CHPCreateApp and gDetector.CHPAddAction) then
    --  Paramters listing <AppId>, <AppType>, <Number of Matches(usually 0, unless to be specified) >
        gDetector:CHPCreateApp(3640, 6, 0);
    -- Parameters listing   <AppId>, 
    --                      <Key Pattern(1) or not(0)>, 
    --                      <Pattern look-up type (User agent -> 0, Host -> 1, Referer -> 2, URI -> 3, Cookie -> 4, Content -> 5, Location -> 6, Body -> 7) >, 
    --                      <Patter string>, 
    --                      <Action type>, 
    --                      <Action String>
        gDetector:CHPAddAction(3640, 1, 1, "amazon", 0, "");
        gDetector:CHPAddAction(3640, 0, 3, "drive", 0, "");
        gDetector:CHPAddAction(3640, 0, 3, "&downloadById=", 5, "3641");
        gDetector:CHPAddAction(3640, 0, 3, "popup", 5, "3641");
        gDetector:CHPAddAction(3640, 0, 3, "popup-upload", 5, "3642");
        gDetector:CHPAddAction(3640, 0, 3, "adrive-uploader", 5, "3642");
        gDetector:CHPAddAction(3640, 0, 3, "&Operation=createById", 5, "3642");
        gDetector:CHPAddAction(3640, 0, 3, "&Operation=completeFileUploadById", 5, "3642");
        gDetector:CHPAddAction(3640, 0, 3, "&Operation=getUploadUrlById", 5, "3642");
        gDetector:CHPAddAction(3640, 0, 3, "&pf_rd_i=clouddrive", 5, "3643");
    end

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector
end

function DetectorValidator()
    local context = {}
    return serviceFail(context)
end

function DetectorFini()
end
