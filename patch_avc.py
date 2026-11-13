from pathlib import Path
import sys
import re

# Patch avc.c
p = Path('security/selinux/avc.c')
if not p.exists():
    sys.exit('FATAL: avc.c not found')

s = p.read_text()
if 'susfs_is_avc_log_spoofing_enabled' not in s:
    decl = '#ifdef CONFIG_KSU_SUSFS\n' \
           'extern u32 susfs_ksu_sid;\n' \
           'extern u32 susfs_priv_app_sid;\n' \
           'extern struct static_key_false susfs_is_avc_log_spoofing_enabled;\n' \
           '#endif\n'

    if '#include "avc.h"' in s:
        s = s.replace('#include "avc.h"', '#include "avc.h"\n' + decl, 1)
    else:
        s = s.replace('#include <linux/lsm_hooks.h>', '#include <linux/lsm_hooks.h>\n' + decl, 1)

    inj = '#ifdef CONFIG_KSU_SUSFS\n' \
          '    if (static_branch_likely(&susfs_is_avc_log_spoofing_enabled)) {\n' \
          '        if (unlikely(sad->tsid == susfs_ksu_sid)) {\n' \
          '            if (rc)\n' \
          '                audit_log_format(ab, " tsid=%d", susfs_priv_app_sid);\n' \
          '            else\n' \
          '                audit_log_format(ab, " tcontext=%s", "u:r:priv_app:s0:c512,c768");\n' \
          '            goto bypass_orig_flow;\n' \
          '        }\n' \
          '    }\n' \
          '#endif\n'

    pattern = r'(rc\s*=\s*security_sid_to_context[^;]+;)'
    if re.search(pattern, s):
        s = re.sub(pattern, r'\1\n' + inj, s, count=1)
    else:
        sys.exit('FATAL: rc = security_sid_to_context not found')

    if 'kfree(scontext);' in s:
        s = s.replace('kfree(scontext);', 'kfree(scontext);\n#ifdef CONFIG_KSU_SUSFS\nbypass_orig_flow:\n#endif', 1)

    p.write_text(s)
    print('SUCCESS: Patched avc.c inline')

# Patch susfs.c
p2 = Path('fs/susfs.c')
if p2.exists():
    s2 = p2.read_text()
    if 'susfs_is_avc_log_spoofing_enabled' not in s2:
        s2 += '\n#ifdef CONFIG_KSU_SUSFS\ndefine_STATIC_KEY_FALSE(susfs_is_avc_log_spoofing_enabled);\nEXPORT_SYMBOL(susfs_is_avc_log_spoofing_enabled);\nu32 susfs_ksu_sid = 0;\nEXPORT_SYMBOL(susfs_ksu_sid);\nu32 susfs_priv_app_sid = 0;\nEXPORT_SYMBOL(susfs_priv_app_sid);\n#endif\n'
        p2.write_text(s2)
        print('SUCCESS: Patched susfs.c')
