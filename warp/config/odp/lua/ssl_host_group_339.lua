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
detection_name: SSL Group "339"
version: 3
description: Group of SSL Host detectors.
bundle_description: $VAR1 = {
          'RingCentral' => 'RingCentral is an American publicly traded provider of cloud-based communications and collaboration solutions for businesses.',
          'Fiserv' => 'Fiserv is a provider of technology solutions to the financial world, including banks, credit unions, securities processing organizations, insurance companies, etc.',
          'QlikView' => 'QlikView is a BI data discovery product for creating guided analytics applications and dashboards tailor-made for business challenges.',
          'Jira' => 'Web based bug tracking and project management tool.',
          'Jaspersoft' => 'Jaspersoft embedded analytics software is a BI platform to design, embed, and manage reports & analytics with programmatic control.',
          'OneLogin' => 'A cloud-based identity and access management service.',
          'Tableau' => 'Tableau Software is an interactive data visualization and data analytics software which provides pictorial and graphical representations of data.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "ssl_host_group_339",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        minimum_matches =  1
    }
}

gSSLHostPatternList = {

    -- Tableau
    {0, 4636, 'tableau.com', },
    -- Fiserv
    {0, 4632, 'fiserv.com', },
    -- RingCentral
    {0, 4635, 'ringcentral.com', },
    -- Qlikview
    {0, 4634, 'qlik.com', },
    -- Jaspersoft
    {0, 4633, 'jaspersoft.com', },
    -- OneLogin
    { 0, 4638, 'service-now.com' },
    { 0, 4638, 'onelogin.com' },
    -- Jira
    { 0, 695, 'jira.com' },

    { 0, 695, 'jira.atlassian.com' },
}

gSSLCnamePatternList = {

    -- Tableau
    {0, 4636, 'tableau.com', },
    -- Fiserv
    {0, 4632, 'fiserv.com', },
    -- RingCentral
    {0, 4635, 'ringcentral.com', },
    -- Qlikview
    {0, 4634, 'qlik.com', },
    -- Jaspersoft
    {0, 4633, 'jaspersoft.com', },
    -- OneLogin
    { 0, 4638, 'service-now.com' },
    { 0, 4638, 'onelogin.com' },

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
