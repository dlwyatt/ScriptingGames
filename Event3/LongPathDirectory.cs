        public static DirectorySecurity GetDacl(string path)
        {
            string normalizedPath = LongPathCommon.NormalizeLongPath(path);
            FileAttributes attributes;

            int errorCode = LongPathCommon.TryGetDirectoryAttributes(normalizedPath, out attributes);

            if (errorCode != 0)
            {
                throw LongPathCommon.GetExceptionFromWin32Error(errorCode);
            }

            IntPtr securityDescriptor;
            IntPtr ignore;

            errorCode = NativeMethods.GetNamedSecurityInfo(normalizedPath, ResourceType.FileObject, SECURITY_INFORMATION.DACL_SECURITY_INFORMATION, out ignore, out ignore, out ignore, out ignore, out securityDescriptor);

            if (errorCode != 0)
            {
                throw LongPathCommon.GetExceptionFromWin32Error(errorCode);
            }

            uint length = NativeMethods.GetSecurityDescriptorLength(securityDescriptor);

            var bytes = new byte[length];

            Marshal.Copy(securityDescriptor, bytes, 0, (int)length);

            var dirSec = new DirectorySecurity();

            dirSec.SetSecurityDescriptorBinaryForm(bytes, AccessControlSections.Access);

            return dirSec;
        }

        public static void SetDacl(string path, DirectorySecurity securityDescriptor)
        {
            string normalizedPath = LongPathCommon.NormalizeLongPath(path);

            if (securityDescriptor == null)
            {
                throw new ArgumentNullException("securityDescriptor");
            }

            var rawSec = new RawSecurityDescriptor(securityDescriptor.GetSecurityDescriptorSddlForm(AccessControlSections.Access));

            var daclBytes = new byte[rawSec.DiscretionaryAcl.BinaryLength];
            rawSec.DiscretionaryAcl.GetBinaryForm(daclBytes, 0);

            SECURITY_INFORMATION secInfo = SECURITY_INFORMATION.DACL_SECURITY_INFORMATION;

            secInfo |= securityDescriptor.AreAccessRulesProtected ? SECURITY_INFORMATION.PROTECTED_DACL_SECURITY_INFORMATION : SECURITY_INFORMATION.UNPROTECTED_DACL_SECURITY_INFORMATION;

            uint errorCode = NativeMethods.SetNamedSecurityInfo(normalizedPath, ResourceType.FileObject, secInfo, null, null, daclBytes, null);

            if (errorCode != 0)
            {
                throw LongPathCommon.GetExceptionFromWin32Error((int)errorCode);
            }
        }