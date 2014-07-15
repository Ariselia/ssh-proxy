#include "ssh-includes.h"
#include "ssh_compat.h"

void
enable_compat20(ssh_session_t *session)
{
	if (session->compat20)
		return;
	trace_out("Enabling compatibility mode for protocol 2.0");
	session->compat20 = 1;
}
void
enable_compat13(ssh_session_t *session)
{
	trace_out("Enabling compatibility mode for protocol 1.3");
	session->compat13 = 1;
}

/* datafellows bug compatibility */
void
compat_datafellows(ssh_session_t *session, const char *version)
{
	int i;
	static struct {
		char *pat;
		int	bugs;
	} check[] = {
		{ "OpenSSH-2.0*,"
		  "OpenSSH-2.1*,"
		  "OpenSSH_2.1*,"
		  "OpenSSH_2.2*",	SSH_OLD_SESSIONID|SSH_BUG_BANNER|
					SSH_OLD_DHGEX|SSH_BUG_NOREKEY|
					SSH_BUG_EXTEOF|SSH_OLD_FORWARD_ADDR},
		{ "OpenSSH_2.3.0*",	SSH_BUG_BANNER|SSH_BUG_BIGENDIANAES|
					SSH_OLD_DHGEX|SSH_BUG_NOREKEY|
					SSH_BUG_EXTEOF|SSH_OLD_FORWARD_ADDR},
		{ "OpenSSH_2.3.*",	SSH_BUG_BIGENDIANAES|SSH_OLD_DHGEX|
					SSH_BUG_NOREKEY|SSH_BUG_EXTEOF|
					SSH_OLD_FORWARD_ADDR},
		{ "OpenSSH_2.5.0p1*,"
		  "OpenSSH_2.5.1p1*",
					SSH_BUG_BIGENDIANAES|SSH_OLD_DHGEX|
					SSH_BUG_NOREKEY|SSH_BUG_EXTEOF|
					SSH_OLD_FORWARD_ADDR},
		{ "OpenSSH_2.5.0*,"
		  "OpenSSH_2.5.1*,"
		  "OpenSSH_2.5.2*",	SSH_OLD_DHGEX|SSH_BUG_NOREKEY|
					SSH_BUG_EXTEOF|SSH_OLD_FORWARD_ADDR},
		{ "OpenSSH_2.5.3*",	SSH_BUG_NOREKEY|SSH_BUG_EXTEOF|
					SSH_OLD_FORWARD_ADDR},
		{ "OpenSSH_2.*,"
		  "OpenSSH_3.0*,"
		  "OpenSSH_3.1*",	SSH_BUG_EXTEOF|SSH_OLD_FORWARD_ADDR},
		{ "OpenSSH_3.*",	SSH_OLD_FORWARD_ADDR },
		{ "Sun_SSH_1.0*",	SSH_BUG_NOREKEY|SSH_BUG_EXTEOF},
		{ "OpenSSH_4*",		0 },
		{ "OpenSSH_5*",		SSH_NEW_OPENSSH|SSH_BUG_DYNAMIC_RPORT},
		{ "OpenSSH*",		SSH_NEW_OPENSSH },
		{ "*MindTerm*",		0 },
		{ "2.1.0*",		SSH_BUG_SIGBLOB|SSH_BUG_HMAC|
					SSH_OLD_SESSIONID|SSH_BUG_DEBUG|
					SSH_BUG_RSASIGMD5|SSH_BUG_HBSERVICE|
					SSH_BUG_FIRSTKEX },
		{ "2.1 *",		SSH_BUG_SIGBLOB|SSH_BUG_HMAC|
					SSH_OLD_SESSIONID|SSH_BUG_DEBUG|
					SSH_BUG_RSASIGMD5|SSH_BUG_HBSERVICE|
					SSH_BUG_FIRSTKEX },
		{ "2.0.13*,"
		  "2.0.14*,"
		  "2.0.15*,"
		  "2.0.16*,"
		  "2.0.17*,"
		  "2.0.18*,"
		  "2.0.19*",		SSH_BUG_SIGBLOB|SSH_BUG_HMAC|
					SSH_OLD_SESSIONID|SSH_BUG_DEBUG|
					SSH_BUG_PKSERVICE|SSH_BUG_X11FWD|
					SSH_BUG_PKOK|SSH_BUG_RSASIGMD5|
					SSH_BUG_HBSERVICE|SSH_BUG_OPENFAILURE|
					SSH_BUG_DUMMYCHAN|SSH_BUG_FIRSTKEX },
		{ "2.0.11*,"
		  "2.0.12*",		SSH_BUG_SIGBLOB|SSH_BUG_HMAC|
					SSH_OLD_SESSIONID|SSH_BUG_DEBUG|
					SSH_BUG_PKSERVICE|SSH_BUG_X11FWD|
					SSH_BUG_PKAUTH|SSH_BUG_PKOK|
					SSH_BUG_RSASIGMD5|SSH_BUG_OPENFAILURE|
					SSH_BUG_DUMMYCHAN|SSH_BUG_FIRSTKEX },
		{ "2.0.*",		SSH_BUG_SIGBLOB|SSH_BUG_HMAC|
					SSH_OLD_SESSIONID|SSH_BUG_DEBUG|
					SSH_BUG_PKSERVICE|SSH_BUG_X11FWD|
					SSH_BUG_PKAUTH|SSH_BUG_PKOK|
					SSH_BUG_RSASIGMD5|SSH_BUG_OPENFAILURE|
					SSH_BUG_DERIVEKEY|SSH_BUG_DUMMYCHAN|
					SSH_BUG_FIRSTKEX },
		{ "2.2.0*,"
		  "2.3.0*",		SSH_BUG_HMAC|SSH_BUG_DEBUG|
					SSH_BUG_RSASIGMD5|SSH_BUG_FIRSTKEX },
		{ "2.3.*",		SSH_BUG_DEBUG|SSH_BUG_RSASIGMD5|
					SSH_BUG_FIRSTKEX },
		{ "2.4",		SSH_OLD_SESSIONID },	/* Van Dyke */
		{ "2.*",		SSH_BUG_DEBUG|SSH_BUG_FIRSTKEX|
					SSH_BUG_RFWD_ADDR },
		{ "3.0.*",		SSH_BUG_DEBUG },
		{ "3.0 SecureCRT*",	SSH_OLD_SESSIONID },
		{ "1.7 SecureFX*",	SSH_OLD_SESSIONID },
		{ "1.2.18*,"
		  "1.2.19*,"
		  "1.2.20*,"
		  "1.2.21*,"
		  "1.2.22*",		SSH_BUG_IGNOREMSG },
		{ "1.3.2*",		/* F-Secure */
					SSH_BUG_IGNOREMSG },
		{ "*SSH Compatible Server*",			/* Netscreen */
					SSH_BUG_PASSWORDPAD },
		{ "*OSU_0*,"
		  "OSU_1.0*,"
		  "OSU_1.1*,"
		  "OSU_1.2*,"
		  "OSU_1.3*,"
		  "OSU_1.4*,"
		  "OSU_1.5alpha1*,"
		  "OSU_1.5alpha2*,"
		  "OSU_1.5alpha3*",	SSH_BUG_PASSWORDPAD },
		{ "*SSH_Version_Mapper*",
					SSH_BUG_SCANNER },
		{ "Probe-*",
					SSH_BUG_PROBE },
		{ NULL,			0 }
	};

	/* process table, return first match */
	for (i = 0; check[i].pat; i++) {
		if (match_pattern_list(version, check[i].pat,
		    strlen(check[i].pat), 0) == 1) {
			session->datafellows = check[i].bugs;
			trace_out("match: %s pat %s compat 0x%08x",
			    version, check[i].pat, session->datafellows);
			return;
		}
	}
	trace_out("no match: %s", version);
}


