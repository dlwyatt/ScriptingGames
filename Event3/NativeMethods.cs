    [Flags]
    internal enum SECURITY_INFORMATION : uint
    {
        OWNER_SECURITY_INFORMATION = 0x00000001,
        GROUP_SECURITY_INFORMATION = 0x00000002,
        DACL_SECURITY_INFORMATION = 0x00000004,
        SACL_SECURITY_INFORMATION = 0x00000008,
        UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000,
        UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000,
        PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000,
        PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
    }

        [DllImport("advapi32.dll", EntryPoint = "GetNamedSecurityInfoW", CharSet = CharSet.Unicode)]
        internal static extern int GetNamedSecurityInfo(string pObjectName,
                                                        ResourceType ObjectType,
                                                        SECURITY_INFORMATION securityInformation,
                                                        out IntPtr pSidOwner,
                                                        out IntPtr pSidGroup,
                                                        out IntPtr pDacl,
                                                        out IntPtr pSacl,
                                                        out IntPtr pSecurityDescriptor);

        [DllImport("advapi32.dll", EntryPoint = "SetNamedSecurityInfoW", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint SetNamedSecurityInfo(string name,
                                                         ResourceType objectType,
                                                         SECURITY_INFORMATION securityInformation,
                                                         byte[] owner,
                                                         byte[] group,
                                                         byte[] dacl,
                                                         byte[] sacl);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint GetSecurityDescriptorLength(IntPtr pSecurityDescriptor);
