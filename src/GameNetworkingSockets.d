module GameNetworkingSockets;

import std.typecons: Typedef;

// steamclientpublic.h
extern (C) enum Result {
	OK     = 1,                                                    // success
	Fail = 2,                                                      // generic failure
	NoConnection = 3,                                      // no/failed network connection
	//      k_EResultNoConnectionRetry = 4,                         // OBSOLETE - removed
	InvalidPassword = 5,                           // password/ticket is invalid
	LoggedInElsewhere = 6,                         // same user logged in elsewhere
	InvalidProtocolVer = 7,                        // protocol version is incorrect
	InvalidParam = 8,                                      // a parameter is incorrect
	FileNotFound = 9,                                      // file was not found
	Busy = 10,                                                     // called method busy - action not taken
	InvalidState = 11,                                     // called object was in an invalid state
	InvalidName = 12,                                      // name is invalid
	InvalidEmail = 13,                                     // email is invalid
	DuplicateName = 14,                            // name is not unique
	AccessDenied = 15,                                     // access is denied
	Timeout = 16,                                          // operation timed out
	Banned = 17,                                           // VAC2 banned
	AccountNotFound = 18,                          // account not found
	InvalidSteamID = 19,                           // steamID is invalid
	ServiceUnavailable = 20,                       // The requested service is currently unavailable
	NotLoggedOn = 21,                                      // The user is not logged on
	Pending = 22,                                          // Request is pending (may be in process, or waiting on third party)
	EncryptionFailure = 23,                        // Encryption or Decryption failed
	InsufficientPrivilege = 24,            // Insufficient privilege
	LimitExceeded = 25,                            // Too much of a good thing
	Revoked = 26,                                          // Access has been revoked (used for revoked guest passes)
	Expired = 27,                                          // License/Guest pass the user is trying to access is expired
	AlreadyRedeemed = 28,                          // Guest pass has already been redeemed by account, cannot be acked again
	DuplicateRequest = 29,                         // The request is a duplicate and the action has already occurred in the past, ignored this time
	AlreadyOwned = 30,                                     // All the games in this guest pass redemption request are already owned by the user
	IPNotFound = 31,                                       // IP address not found
	PersistFailed = 32,                            // failed to write change to the data store
	LockingFailed = 33,                            // failed to acquire access lock for this operation
	LogonSessionReplaced = 34,
	ConnectFailed = 35,
	HandshakeFailed = 36,
	IOFailure = 37,
	RemoteDisconnect = 38,
	ShoppingCartNotFound = 39,                     // failed to find the shopping cart requested
	Blocked = 40,                                          // a user didn't allow it
	Ignored = 41,                                          // target is ignoring sender
	NoMatch = 42,                                          // nothing matching the request found
	AccountDisabled = 43,
	ServiceReadOnly = 44,                          // this service is not accepting content changes right now
	AccountNotFeatured = 45,                       // account doesn't have value, so this feature isn't available
	AdministratorOK = 46,                          // allowed to take this action, but only because requester is admin
	ContentVersion = 47,                           // A Version mismatch in content transmitted within the Steam protocol.
	TryAnotherCM = 48,                                     // The current CM can't service the user making a request, user should try another.
	PasswordRequiredToKickSession = 49,// You are already logged in elsewhere, this cached credential login has failed.
	AlreadyLoggedInElsewhere = 50,         // You are already logged in elsewhere, you must wait
	Suspended = 51,                                        // Long running operation (content download) suspended/paused
	Cancelled = 52,                                        // Operation canceled (typically by user: content download)
	DataCorruption = 53,                           // Operation canceled because data is ill formed or unrecoverable
	DiskFull = 54,                                         // Operation canceled - not enough disk space.
	RemoteCallFailed = 55,                         // an remote call or IPC call failed
	PasswordUnset = 56,                            // Password could not be verified as it's unset server side
	ExternalAccountUnlinked = 57,          // External account (PSN, Facebook...) is not linked to a Steam account
	PSNTicketInvalid = 58,                         // PSN ticket was invalid
	ExternalAccountAlreadyLinked = 59,     // External account (PSN, Facebook...) is already linked to some other account, must explicitly request to replace/delete the link first
	RemoteFileConflict = 60,                       // The sync cannot resume due to a conflict between the local and remote files
	IllegalPassword = 61,                          // The requested new password is not legal
	SameAsPreviousValue = 62,                      // new value is the same as the old one ( secret question and answer )
	AccountLogonDenied = 63,                       // account login denied due to 2nd factor authentication failure
	CannotUseOldPassword = 64,                     // The requested new password is not legal
	InvalidLoginAuthCode = 65,                     // account login denied due to auth code invalid
	AccountLogonDeniedNoMail = 66,         // account login denied due to 2nd factor auth failure - and no mail has been sent
	HardwareNotCapableOfIPT = 67,          //
	IPTInitError = 68,                                     //
	ParentalControlRestricted = 69,        // operation failed due to parental control restrictions for current user
	FacebookQueryError = 70,                       // Facebook query returned an error
	ExpiredLoginAuthCode = 71,                     // account login denied due to auth code expired
	IPLoginRestrictionFailed = 72,
	AccountLockedDown = 73,
	AccountLogonDeniedVerifiedEmailRequired = 74,
	NoMatchingURL = 75,
	BadResponse = 76,                                      // parse failure, missing field, etc.
	RequirePasswordReEntry = 77,           // The user cannot complete the action until they re-enter their password
	ValueOutOfRange = 78,                          // the value entered is outside the acceptable range
	UnexpectedError = 79,                          // something happened that we didn't expect to ever happen
	Disabled = 80,                                         // The requested service has been configured to be unavailable
	InvalidCEGSubmission = 81,                     // The set of files submitted to the CEG server are not valid !
	RestrictedDevice = 82,                         // The device being used is not allowed to perform this action
	RegionLocked = 83,                                     // The action could not be complete because it is region restricted
	RateLimitExceeded = 84,                        // Temporary rate limit exceeded, try again later, different from k_EResultLimitExceeded which may be permanent
	AccountLoginDeniedNeedTwoFactor = 85,  // Need two-factor code to login
	ItemDeleted = 86,                                      // The thing we're trying to access has been deleted
	AccountLoginDeniedThrottle = 87,       // login attempt failed, try to throttle response to possible attacker
	TwoFactorCodeMismatch = 88,            // two factor code mismatch
	TwoFactorActivationCodeMismatch = 89,  // activation code for two-factor didn't match
	AccountAssociatedToMultiplePartners = 90,      // account has been associated with multiple partners
	NotModified = 91,                                      // data not modified
	NoMobileDevice = 92,                           // the account does not have a mobile device associated with it
	TimeNotSynced = 93,                            // the time presented is out of range or tolerance
	SmsCodeFailed = 94,                            // SMS code failure (no match, none pending, etc.)
	AccountLimitExceeded = 95,                     // Too many accounts access this resource
	AccountActivityLimitExceeded = 96,     // Too many changes to this account
	PhoneActivityLimitExceeded = 97,       // Too many changes to this phone
	RefundToWallet = 98,                           // Cannot refund to payment method, must use wallet
	EmailSendFailure = 99,                         // Cannot send an email
	NotSettled = 100,                                      // Can't perform operation till payment has settled
	NeedCaptcha = 101,                                     // Needs to provide a valid captcha
	GSLTDenied = 102,                                      // a game server login token owned by this token's owner has been banned
	GSOwnerDenied = 103,                           // game server owner is denied for other reason (account lock, community ban, vac ban, missing phone)
	InvalidItemType = 104,                         // the type of thing we were requested to act on is invalid
	IPBanned = 105,                                        // the ip address has been banned from taking this action
	GSLTExpired = 106,                                     // this token has expired from disuse; can be reset for use
	InsufficientFunds = 107,                       // user doesn't have enough wallet funds to complete the action
	TooManyPending = 108,                          // There are too many of this thing pending already
	NoSiteLicensesFound = 109,                     // No site licenses found
	WGNetworkSendExceeded = 110,           // the WG couldn't send a response because we exceeded max network send size
}
extern (C++) class CSteamID {
	// hopefully just marking it extern (C++) generates the vtbl pointer and
	// pads out the length.  Or alternately that's not how c++ works and the
	// vtbl is elsewhere.  Whatever the case may be, I really hope that this
	// works because I don't want to fix it else ;)  (also, justified text!)
	ulong all_64_bits;
}
// commented out because seriously, why would you use this??
/+
enum Universe {
	Invalid = 0,
	Public = 1,
	Beta = 2,
	Internal = 3,
	Dev = 4,
	// RC = 5,
	Max,
}
struct SteamID_Component {
	Universe universe, // 8 bits
	ubyte account_type, // 4 bits
	uint account_instance, // 20 bits
	uint accountID, // 32 bits
}
SteamID_Component get_component(CSteamID id) {
	SteamID_Component ret;
	ulong bits = id.all_64_bits;

	version (BigEndian) {
		ret.universe = bits & 0xff00_0000_0000_0000;
		ret.account_type = bits & 0x00f0_0000_0000_0000;
		ret.account_instance = bits & 0x000f_ffff_0000_0000;
		ret.accountID = bits & 0xffff_ffff;
	} else {
		ret.accountID = bits & 0xffff_ffff_0000_0000;
		ret.account_instance = bits & 0xffff_f000;
		ret.account_type = bits & 0x0f00;
		ret.universe = bits & 0xff;
	}

	return ret;
}
+/



// steamnetworkingtypes.h
alias Microseconds = Typedef!(long, long.init, "Microseconds");
alias NetConnection = Typedef!(uint, uint.init, "NetConnection");
alias ListenSocket = Typedef!(uint, uint.init, "ListenSocket");
alias POPID = Typedef!(uint, uint.init, "POPID");

enum SendFlags {
	NoNagle = 1,
	NoDelay = 2,
	Reliable = 8,
}

// stolen directly from the original header
enum NetworkingSendType {
	// Send an unreliable message. Can be lost.  Messages *can* be larger than a single MTU (UDP packet), but there is no
	// retransmission, so if any piece of the message is lost, the entire message will be dropped.
	//
	// The sending API does have some knowledge of the underlying connection, so if there is no NAT-traversal accomplished or
	// there is a recognized adjustment happening on the connection, the packet will be batched until the connection is open again.
	//
	// NOTE: By default, Nagle's algorithm is applied to all outbound packets.  This means that the message will NOT be sent
	//       immediately, in case further messages are sent soon after you send this, which can be grouped together.
	//       Any time there is enough buffered data to fill a packet, the packets will be pushed out immediately, but
	//       partially-full packets not be sent until the Nagle timer expires.
	//       See k_ESteamNetworkingSendType_UnreliableNoNagle, ISteamNetworkingSockets::FlushMessagesOnConnection,
	//       ISteamNetworkingP2P::FlushMessagesToUser
	//
	// This is not exactly the same as k_EP2PSendUnreliable!  You probably want k_ESteamNetworkingSendType_UnreliableNoNagle
	Unreliable = 0,

	// Send a message unreliably, bypassing Nagle's algorithm for this message and any messages currently pending on the Nagle timer.
	// This is equivalent to using k_ESteamNetworkingSendType_Unreliable,
	// and then immediately flushing the messages using ISteamNetworkingSockets::FlushMessagesOnConnection or ISteamNetworkingP2P::FlushMessagesToUser.
	// (But this is more efficient.)
	UnreliableNoNagle = SendFlags.NoNagle,

	// Send an unreliable message, but do not buffer it if it cannot be sent relatively quickly.
	// This is useful for messages that are not useful if they are excessively delayed, such as voice data.
	// The Nagle algorithm is not used, and if the message is not dropped, any messages waiting on the Nagle timer
	// are immediately flushed.
	//
	// A message will be dropped under the following circumstances:
	// - the connection is not fully connected.  (E.g. the "Connecting" or "FindingRoute" states)
	// - there is a sufficiently large number of messages queued up already such that the current message
	//   will not be placed on the wire in the next ~200ms or so.
	//
	// if a message is dropped for these reasons, k_EResultIgnored will be returned.
	UnreliableNoDelay = SendFlags.NoDelay|SendFlags.NoNagle,

	// Reliable message send. Can send up to 512kb of data in a single message.
	// Does fragmentation/re-assembly of messages under the hood, as well as a sliding window for
	// efficient sends of large chunks of data.
	//
	// The Nagle algorithm is used.  See notes on k_ESteamNetworkingSendType_Unreliable for more details.
	// See k_ESteamNetworkingSendType_ReliableNoNagle, ISteamNetworkingSockets::FlushMessagesOnConnection,
	// ISteamNetworkingP2P::FlushMessagesToUser
	//
	// This is NOT the same as k_EP2PSendReliable, it's more like k_EP2PSendReliableWithBuffering
	Reliable = SendFlags.Reliable,

	// Send a message reliably, but bypass Nagle's algorithm.
	// See k_ESteamNetworkingSendType_UnreliableNoNagle for more info.
	//
	// This is equivalent to k_EP2PSendReliable
	ReliableNoNagle = SendFlags.Reliable|SendFlags.NoNagle,
}

extern (C) struct ConnectionStatusChangedCallback_t{};
extern (C) struct Message {
	CSteamID sender;
	long user_data;
	Microseconds time_received;
	long message_number;
	void function(Message*) fn_release;
	void *data;
	uint size;
	NetConnection conn;
	int channel;
	int _pad; // I think there's a d pragma for this but I don't remember what it is and don't want to screw the alignment up because that would be Bad
	extern (D) void release() {
		this.fn_release(&this);
	}
}
extern (C) struct ConnectionInfo {
	ListenSocket socket;
	CSteamID remote;
	long user_data;
	uint ip_remote;
	ushort port_remote;
	ushort _pad;
	POPID POPRelay;
	int state;
	int end_reason;
	char[128] end_debug; // fun fact: that '128' was stored in a variable, only used once, called 'k_cchSteamNetworkingMaxConnectionCloseReason'.  That's not even java!!
}
extern (C) struct QuickConnectionInfo {
	int state;
	int ping;
	float conn_quality_local;
	float conn_quality_remote;
	float out_packets_per_sec;
	float out_bytes_per_sec;
	float in_packets_per_sec;
	float in_bytes_per_sec;
	int channel_capacity; // renamed from m_nSendRateBytesPerSecond
	int pending_unreliable;
	int pending_reliable;
	int sent_unacked_reliable;
	Microseconds usec_queue_time;
}

enum ConfigurationValue {
	FakeMessageLoss_Send = 0,
	FakeMessageLoss_Recv = 1,
	FakePacketLoss_Send = 2,
	FakePacketLoss_Recv = 3,
	FakePacketLag_Send = 4,
	FakePacketLag_Recv = 5,
	FakePacketReorder_Send = 6,
	FakePacketReorder_Recv = 7,
	FakePacketReorder_Time = 8,
	SendBufferSize = 9,
	MaxRate = 10,
	MinRate = 11,
	Nagle_Time = 12,
	LogLevel_AckRTT = 13,
	LogLevel_Packet = 14,
	LogLevel_Message = 15,
	LogLevel_PacketGaps = 16,
	LogLevel_P2PRendezvous = 17,
	LogLevel_RelayPings = 18,
	ClientConsecutitivePingTimeoutsFailInitial = 19,
	ClientConsecutitivePingTimeoutsFail = 20,
	ClientMinPingsBeforePingAccurate = 21,
	ClientSingleSocket = 22,
	IP_Allow_Without_Auth = 23,
	Timeout_Seconds_Initial = 24,
	Timeout_Seconds_Connected = 25,
	Count,
}

enum ConfigurationString {
	ClientForceRelayCluster = 0,
	ClientDebugTicketAddress = 1,
	ClientForceProxyAddr = 2,
	Count
}



// steamnetworksockets_flat.h
extern (C) {
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_CreateListenSocket") ListenSocket CreateListenSocket(ptrdiff_t instance_ptr, int steam_connect_virtual_port, uint ip, ushort port);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_ConnectByIPv4Address") NetConnection ConnectByIPv4Address(ptrdiff_t instance_ptr, uint ip, ushort port);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_AcceptConnection") Result AcceptConnection(ptrdiff_t instance_ptr, NetConnection conn);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_CloseConnection") bool CloseConnection(ptrdiff_t instance_ptr, NetConnection peer, int reason, const char *debug_, bool enable_linger);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_CloseListenSocket") bool CloseListenSocket(ptrdiff_t instance_ptr, ListenSocket socket, const char *notify_remote_reason);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_SetConnectionUserData") bool SetConnectionUserData(ptrdiff_t instance_ptr, NetConnection peer, long user_data);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_GetConnectionUserData") long GetConnectionUserData(ptrdiff_t instance_ptr, NetConnection peer);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_SetConnectionName") void SetConnectionName(ptrdiff_t instance_ptr, NetConnection peer, const char *name);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_GetConnectionUserData") long GetConnectionUserData(ptrdiff_t instance_ptr, NetConnection peer, const char *name, int max_len);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_SendMessageToConnection") Result SendMessageToConnection(ptrdiff_t instance_ptr, NetConnection conn, const void *data, uint len /* NB: Valve, y u 32-bit?? */, NetworkingSendType send_type);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_FlushMessagesOnConnection") Result FlushMessagesOnConnection(ptrdiff_t instance_ptr, NetConnection conn);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnConnection") int ReceiveMessagesOnConnection(ptrdiff_t instance_ptr, NetConnection conn, Message **out_messages, int max_messages);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnListenSocket") int ReceiveMessagesOnListenSocket(ptrdiff_t instance_ptr, ListenSocket socket, Message **out_messages, int max_messages);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_GetConnectionInfo") bool GetConnectionInfo(ptrdiff_t instance_ptr, NetConnection conn, ConnectionInfo *info);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_GetQuickConnectionStatus") bool GetQuickConnectionStatus(ptrdiff_t instance_ptr, NetConnection conn, QuickConnectionInfo *info);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_GetDetailedConnectionStatus") int GetDetailedConnectionStatus(ptrdiff_t instance_ptr, NetConnection conn, char *buf, int len);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_GetListenSocketInfo") bool GetListenSocketInfo(ptrdiff_t instance_ptr, ListenSocket socket, uint *ip, ushort *port);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_CreateSocketPair") bool CreateSocketPair(ptrdiff_t instance_ptr, NetConnection *conn1, NetConnection *conn2, bool use_network_loopback);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_GetConnectionDebugText") bool GetConnectionDebugText(ptrdiff_t instance_ptr, NetConnection conn, char *target, int target_capacity);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_GetConfigurationValue") int GetConfigurationValue(ptrdiff_t instance_ptr, ConfigurationValue value);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_SetConfigurationValue") bool SetConfigurationValue(ptrdiff_t instance_ptr, ConfigurationValue key, int value);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_GetConfigurationValueName") const(char*) GetConfigurationValueName(ptrdiff_t instance_ptr, ConfigurationValue value);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_GetConfigurationString") int GetConfigurationString(ptrdiff_t instance_ptr, ConfigurationString config_str, char *dest, int destsz);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_SetConfigurationString") bool SetConfigurationString(ptrdiff_t instance_ptr, ConfigurationString config_str, const char *str);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_GetConfigurationStringName") const(char*) GetConfigurationStringName(ptrdiff_t instance_ptr, ConfigurationString config_str);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_GetConnectionConfigurationValue") int GetConnectionConfigurationValue(ptrdiff_t instance_ptr, NetConnection conn, ConfigurationValue value);
	pragma(mangle, "SteamAPI_ISteamNetworkingSockets_SetConnectionConfigurationValue") bool SetConnectionConfigurationValue(ptrdiff_t instance_ptr, NetConnection conn, ConfigurationValue key, int value);

	alias ConnectionStatusChangedCallback = void *function(ConnectionStatusChangedCallback_t *info, ptrdiff_t context);
	pragma(mangle, "GameNetworkingSockets_RunConnectionStatusChangedCallbacks") void RunConnectionStatusChangedCallbacks(ptrdiff_t instance_ptr, ConnectionStatusChangedCallback callback, ptrdiff_t context);
}

// isteamnetworkingsockets.h (c++ code)
enum NetworkingCallbacks = 1200;
extern (C++) abstract class ISteamNetworkingSockets{
public:
	ListenSocket CreateListenSocket(int steam_connect_virtual_port, uint ip, ushort port);
	NetConnection ConnectByIPv4Address(uint ip, ushort port);
	Result AcceptConnection(NetConnection conn);
	bool CloseConnection(NetConnection peer, int reason, const char *debug_, bool enable_linger);
	bool CloseListenSocket(ListenSocket socket, const char *notify_remote_reason);
	bool SetConnectionUserData(NetConnection peer, long user_data);
	long GetConnectionUserData(NetConnection peer);
	void SetConnectionName(NetConnection peer, const char *name);
	bool GetConnectionName(NetConnection peer, char *name, int max_len);
	Result SendMessageToConnection(NetConnection con, const void *data, uint len, NetworkingSendType send_type);
	Result FlushMessagesOnConnection(NetConnection conn);
	int ReceiveMessagesOnConnection(NetConnection conn, Message **out_messages, int max_messages);
	int ReceiveMessagesOnListenSocket(ListenSocket socket, Message **out_messages, int max_messages);
	bool GetConnectionInfo(NetConnection conn, ConnectionInfo *info);
	bool GetQuickConnectionStatus(NetConnection conn, QuickConnectionInfo *info);
	int GetDetailedConnectionStatus(NetConnection conn, char *buf, int len);
	bool GetListenSocketInfo(ListenSocket socket, uint *ip, ushort *port);
	bool CreateSocketPair(NetConnection *conn1, NetConnection *conn2, bool use_network_loopback);
	bool GetConnectionDebugText(NetConnection conn, char *buf, int len);
	int GetConfigurationValue(ConfigurationValue value);
	bool SetConfigurationValue(ConfigurationValue key, int value);
	const char *GetConfigurationValueName(ConfigurationValue value);
	int GetConfigurationString(ConfigurationString key, char *dest, int len);
	bool SetConfigurationString(ConfigurationString key, const char *value);
	const char *GetConfigurationStringName(ConfigurationString key);
	int GetConnectionConfigurationValue(NetConnection conn, ConfigurationValue value);
	bool SetConnectionConfigurationValue(NetConnection conn, ConfigurationValue key, int value);
	void RunCallbacks(SocketsCallbacks *callbacks);
	protected ~this();
};
private enum DgramErrMsgLen = 1024;
extern (C) ISteamNetworkingSockets *SteamNetworkingSockets();
extern (C) ISteamNetworkingSockets *SteamNetworkingSocketsGameServer();
extern (C++) bool GameNetworkingSockets_Init(ref char[DgramErrMsgLen] errMsg);
extern (C) void GameNetworkingSockets_Kill();

// TODO
extern (C++) class SocketsCallbacks {}
