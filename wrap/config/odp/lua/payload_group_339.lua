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
detection_name: Payload Group "339"
version: 3
description: Group of payload detectors.
bundle_description: $VAR1 = {
          'Tableau' => 'Tableau Software is an interactive data visualization and data analytics software which provides pictorial and graphical representations of data.',
          'RingCentral' => 'RingCentral is an American publicly traded provider of cloud-based communications and collaboration solutions for businesses.',
          'QlikView' => 'QlikView is a BI data discovery product for creating guided analytics applications and dashboards tailor-made for business challenges.',
          'OneLogin' => 'A cloud-based identity and access management service.',
          'Jaspersoft' => 'Jaspersoft embedded analytics software is a BI platform to design, embed, and manage reports & analytics with programmatic control.',
          'Fiserv' => 'Fiserv is a provider of technology solutions to the financial world, including banks, credit unions, securities processing organizations, insurance companies, etc.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "payload_group_339",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gUrlPatternList = {

    -- Fiserv
    { 0, 0, 0, 1946, 39, "fiserv.com", "/", "http:", "", 4632},
    -- Jaspersoft
    { 0, 0, 0, 1948, 47, "jaspersoft.com", "/", "http:", "", 4633},
    -- Qlikview
    { 0, 0, 0, 1949, 43, "qlik.com", "/", "http:", "", 4634},
    -- RingCentral
    { 0, 0, 0, 1950, 8, "ringcentral.com", "/", "http:", "", 4635},
    -- Tableau
    { 0, 0, 0, 1951, 8, "tableau.com", "/", "http:", "", 4636},
    -- OneLogin
    { 0, 0, 0, 1952, 83, "service-now.com", "/", "http:", "", 4638},
    { 0, 0, 0, 1952, 83, "onelogin.com", "/", "http:", "", 4638},

}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addAppUrl then
        for i,v in ipairs(gUrlPatternList) do
            gDetector:addAppUrl(v[1],v[2],v[3],v[4],v[5],v[6],v[7],v[8],v[9],v[10]);
        end
    end

    return gDetector;
end

function DetectorClean()
end

