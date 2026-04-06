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
detection_name: Flickr
version: 11
description: An image hosting and video hosting website, web services suite, and online community.
bundle_description: $VAR1 = {
          'Flickr' => 'An image hosting and video hosting website, web services suite, and online community.'
        };

--]]

require "DetectorCommon"


local DC = DetectorCommon

DetectorPackageInfo = {
    name =  "Flickr Safesearch",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
        validate =  'DetectorValidator',
        minimum_matches =  1
    }
}

function DetectorClean()
end

function DetectorInit(detectorInstance)
    gDetector = detectorInstance
    if (gDetector.CHPMultiCreateApp and gDetector.CHPMultiAddAction) then
        local handle
        handle = gDetector:CHPMultiCreateApp(159, 4, 2);
        gDetector:CHPMultiAddAction(handle, 1, 1, "www.flickr.", 13, "");
        gDetector:CHPMultiAddAction(handle, 0, 3, "search/?", 0, "");
        -- remove the unsafe URI parameter
        gDetector:CHPMultiAddAction(handle, 0, 3, "safe_search=3", 3, "safe_search=1");
        gDetector:CHPMultiAddAction(handle, 0, 3, "safe_search=2", 3, "safe_search=1");
        gDetector:CHPMultiAddAction(handle, 0, 3, "search/?", 4, "safe_search=1");
        gDetector:CHPMultiAddAction(handle, 0, 3, "safe_search=1text", 3, "safe_search=1&text");

        handle = gDetector:CHPMultiCreateApp(159, 4, 2);
        gDetector:CHPMultiAddAction(handle, 1, 1, "api.flickr.", 13, "");
        gDetector:CHPMultiAddAction(handle, 0, 3, "/rest?", 0, "");
        -- remove the unsafe URI parameter
        gDetector:CHPMultiAddAction(handle, 0, 3, "safe_search=3", 3, "safe_search=1");
        gDetector:CHPMultiAddAction(handle, 0, 3, "safe_search=2", 3, "safe_search=1");
        gDetector:CHPMultiAddAction(handle, 0, 3, "/rest?", 4, "safe_search=1&");

        handle = gDetector:CHPMultiCreateApp(159, 4, 2);
        gDetector:CHPMultiAddAction(handle, 1, 1, "static.flickr.", 13, "");
        gDetector:CHPMultiAddAction(handle, 0, 3, "search/?", 0, "");
        -- remove the unsafe URI parameter
        gDetector:CHPMultiAddAction(handle, 0, 3, "safe_search=3", 3, "safe_search=1");
        gDetector:CHPMultiAddAction(handle, 0, 3, "safe_search=2", 3, "safe_search=1");
        gDetector:CHPMultiAddAction(handle, 0, 3, "search/?", 4, "safe_search=1&");
    end
    return gDetector
end

function DetectorValidator()
    local context = {}
    return serviceFail(context)
end

function DetectorFini()
end
