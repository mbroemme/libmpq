/* Copyright (c) 2026 Maik Broemme. LGPL-2.1-or-later. */
package org.libmpq;

/** One stored filename identity; flags describe classic/BET provenance. */
public record FileIdentity(int fileNumber, int flags, int locale, int platform) { }
