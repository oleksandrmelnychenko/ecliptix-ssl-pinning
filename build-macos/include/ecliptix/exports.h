
#ifndef ECLIPTIX_API_H
#define ECLIPTIX_API_H

#ifdef ECLIPTIX_STATIC_DEFINE
#  define ECLIPTIX_API
#  define ECLIPTIX_NO_EXPORT
#else
#  ifndef ECLIPTIX_API
#    ifdef ecliptix_security_EXPORTS
        /* We are building this library */
#      define ECLIPTIX_API __attribute__((visibility("default")))
#    else
        /* We are using this library */
#      define ECLIPTIX_API __attribute__((visibility("default")))
#    endif
#  endif

#  ifndef ECLIPTIX_NO_EXPORT
#    define ECLIPTIX_NO_EXPORT __attribute__((visibility("hidden")))
#  endif
#endif

#ifndef ECLIPTIX_DEPRECATED
#  define ECLIPTIX_DEPRECATED __attribute__ ((__deprecated__))
#endif

#ifndef ECLIPTIX_DEPRECATED_EXPORT
#  define ECLIPTIX_DEPRECATED_EXPORT ECLIPTIX_API ECLIPTIX_DEPRECATED
#endif

#ifndef ECLIPTIX_DEPRECATED_NO_EXPORT
#  define ECLIPTIX_DEPRECATED_NO_EXPORT ECLIPTIX_NO_EXPORT ECLIPTIX_DEPRECATED
#endif

/* NOLINTNEXTLINE(readability-avoid-unconditional-preprocessor-if) */
#if 0 /* DEFINE_NO_DEPRECATED */
#  ifndef ECLIPTIX_NO_DEPRECATED
#    define ECLIPTIX_NO_DEPRECATED
#  endif
#endif

#endif /* ECLIPTIX_API_H */
