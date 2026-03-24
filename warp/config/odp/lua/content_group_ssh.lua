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
detection_name: Content Group "SSH"
version: 2
description: Group of detectors for SSH Clients.
bundle_description: $VAR1 = {
          'libssh2' => 'A client-side C library implementing the SSH2 protocol.',
          'MobaXterm' => 'Xserver and tabbed SSH client for Windows.',
          'OpenSSH' => 'SSH client.',
          'Trilead SSH-2' => 'A Java implementation of the SSH protocol.',
          'PuTTY' => 'SSH client.',
          'lsh' => 'Freeware SSH implementation.',
          'WinSCP' => 'A free SFTP and FTP client for Windows.',
          'Dropbear' => 'SSH client.'
        };

--]]

require "DetectorCommon"

local DC = DetectorCommon

DetectorPackageInfo = {
    name = "content_group_ssh",
    proto =  DC.ipproto.tcp,
    client = {
        init =  'DetectorInit',
        clean =  'DetectorClean',
    }
}

gSSHPatternList = {
    { "OpenSSH", 771 },
    { "PuTTY", 794 },
    { "lsh", 723 },
    { "dropbear", 619 },
    { "libssh2", 4656 },
    { "TrileadSSH2Java", 4657 },
    { "WinSCP", 4658 },
    { "MoTTY", 4659 },
}

function DetectorInit(detectorInstance)

    gDetector = detectorInstance;

    if gDetector.addSSHPattern then
        for i,v in ipairs(gSSHPatternList) do
            gDetector:addSSHPattern(v[1], v[2]);
        end
    end
    return gDetector;
end

function DetectorClean()
end
