using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Windows.Win32.Security;

namespace AccessCheckTests;

[TestClass]
public unsafe class AccessCheckTest
{
	private static SafeFileHandle handle = default!;
	private static FileSecurity security = new();
	private static byte[] securityBuffer = default!;

	[ClassInitialize]
	public static void Setup(TestContext context)
	{
		var user = WindowsIdentity.GetCurrent().User!;
		security.SetOwner(user);
		security.SetGroup(new SecurityIdentifier(WellKnownSidType.NullSid, null));
		security.AddAccessRule(
			new FileSystemAccessRule(
				user, FileSystemRights.FullControl, AccessControlType.Allow));

		OpenProcessToken(GetCurrentProcess_SafeHandle(), TOKEN_ACCESS_MASK.TOKEN_ALL_ACCESS, out var process);
		using (process)
		{
			DuplicateToken(process, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, out handle);
		}

		securityBuffer = security.GetSecurityDescriptorBinaryForm();
	}

	[ClassCleanup]
	public static void Cleanup()
	{
		handle?.Dispose();
	}

	[TestMethod]
	public void PassNullNull()
	{
		bool result;
		fixed (byte* securityBufferLocal = securityBuffer)
		{
			GENERIC_MAPPING mapping = default;
			PSECURITY_DESCRIPTOR descriptor = (PSECURITY_DESCRIPTOR)securityBufferLocal;
			result = AccessCheck(descriptor, handle, (uint)FILE_GENERIC_READ, mapping, null, ref NullRef<uint>(), out var granted, out var access);
			var lastError = Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error());
			Assert.IsTrue(result, "Erroneous false returned, granted: {0:X}, access: {1}. Last Error: {2}", granted, access, lastError);
			Assert.IsTrue(access, "Access not granted, {0:X}. Last Error: {1}", granted, lastError);
		}
	}

	[TestMethod]
	public void PassNullZero()
	{
		bool result;
		fixed (byte* securityBufferLocal = securityBuffer)
		{
			GENERIC_MAPPING mapping = default;
			PSECURITY_DESCRIPTOR descriptor = (PSECURITY_DESCRIPTOR)securityBufferLocal;
			uint length = 0;
			result = AccessCheck(descriptor, handle, (uint)FILE_GENERIC_READ, mapping, null, ref length, out var granted, out var access);
			var lastError = Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error());
			Assert.IsTrue(result, "Erroneous false returned, granted: {0:X}, access: {1}. Last Error: {2}", granted, access, lastError);
			Assert.IsTrue(access, "Access not granted, {0:X}. Last Error: {1}", granted, lastError);
		}
	}

	[TestMethod]
	public void PassNullSize()
	{
		bool result;
		fixed (byte* securityBufferLocal = securityBuffer)
		{
			GENERIC_MAPPING mapping = default;
			PSECURITY_DESCRIPTOR descriptor = (PSECURITY_DESCRIPTOR)securityBufferLocal;
			uint length = (uint)SizeOf<PRIVILEGE_SET>();
			result = AccessCheck(descriptor, handle, (uint)FILE_GENERIC_READ, mapping, null, ref length, out var granted, out var access);
			var lastError = Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error());
			Assert.IsTrue(result, "Erroneous false returned, granted: {0:X}, access: {1}. Last Error: {2}", granted, access, lastError);
			Assert.IsTrue(access, "Access not granted, {0:X}. Last Error: {1}", granted, lastError);
		}
	}

	[TestMethod]
	public void PassPtrZero()
	{
		bool result;
		fixed (byte* securityBufferLocal = securityBuffer)
		{
			GENERIC_MAPPING mapping = default;
			PSECURITY_DESCRIPTOR descriptor = (PSECURITY_DESCRIPTOR)securityBufferLocal;
			PRIVILEGE_SET set = default!;
			uint length = 0;
			result = AccessCheck(descriptor, handle, (uint)FILE_GENERIC_READ, mapping, &set, ref length, out var granted, out var access);
			var lastError = Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error());
			Assert.IsTrue(result, "Erroneous false returned, granted: {0:X}, access: {1}. Last Error: {2}", granted, access, lastError);
			Assert.IsTrue(access, "Access not granted, {0:X}. Last Error: {1}", granted, lastError);
		}
	}

	[TestMethod]
	public void PassPtrSize()
	{
		bool result;
		fixed (byte* securityBufferLocal = securityBuffer)
		{
			GENERIC_MAPPING mapping = default;
			PSECURITY_DESCRIPTOR descriptor = (PSECURITY_DESCRIPTOR)securityBufferLocal;
			PRIVILEGE_SET set = default!;
			uint length = (uint)SizeOf<PRIVILEGE_SET>();
			result = AccessCheck(descriptor, handle, (uint)FILE_GENERIC_READ, mapping, &set, ref length, out var granted, out var access);
			var lastError = Marshal.GetExceptionForHR(Marshal.GetHRForLastWin32Error());
			Assert.IsTrue(result, "Erroneous false returned, granted: {0:X}, access: {1}. Last Error: {2}", granted, access, lastError);
			Assert.IsTrue(access, "Access not granted, {0:X}. Last Error: {1}", granted, lastError);
		}
	}
}