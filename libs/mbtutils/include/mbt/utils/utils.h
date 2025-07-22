#ifndef MBT_UTILS_UTILS_H
#define MBT_UTILS_UTILS_H

////////////////////////////////////////////////////////////////////////////////
/// THIS FILE WILL BE OVERWRITTEN                                            ///
////////////////////////////////////////////////////////////////////////////////

// see the Attributes section in the subject
#define MBT_ATTR(...) __attribute__((__VA_ARGS__))
#define MBT_UNUSED MBT_ATTR(unused)
#define MBT_PACKED MBT_ATTR(packed)
#define MBT_NONNULL(...) MBT_ATTR(nonnull(__VA_ARGS__))
#define MBT_RET_NONNULL MBT_ATTR(returns_nonnull)

#define MBT_UNREACHABLE() __builtin_unreachable()

#endif /* !MBT_UTILS_UTILS_H */
