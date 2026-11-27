use crate::*;

/// The translation table. See [`K`] for why it is a match and what is deliberately absent
/// from it.
pub(crate) fn t(lang: Lang, key: K) -> &'static str {
    match key {
        K::Dashboard => m(lang, "Dashboard", "Cruscotto"),
        K::Config => m(lang, "System settings", "Impostazioni di sistema"),
        K::ConfigTab => m(lang, "Settings", "Impostazioni"),
        K::NavMenu => m(lang, "Navigation menu", "Menu di navigazione"),
        K::ConfigIntro => m(
            lang,
            "The settings that take effect with no restart. Everything else bb-auth is configured with stays in its env file, on the host.",
            "Le impostazioni che hanno effetto senza riavvio. Tutto il resto della configurazione di bb-auth resta nel suo file di environment, sull'host.",
        ),
        K::ConfigAccess => m(lang, "Access policy", "Politica di accesso"),
        K::ConfigHandover => m(
            lang,
            "What the application receives",
            "Cosa riceve l'applicazione",
        ),
        K::ConfigSignIn => m(lang, "The sign-in page", "La pagina di accesso"),
        K::ConfigAdminLook => m(lang, "Administration and look", "Amministrazione e aspetto"),
        K::ConfigAudit => m(lang, "What the audit records", "Cosa registra l'audit"),
        K::ClientIpHeader => m(
            lang,
            "Client address header",
            "Header dell'indirizzo del client",
        ),
        K::ClientIpHeaderHelp => m(
            lang,
            "The request header the audit reads the client's address from, such as X-Real-IP. Empty records no address. Name it only once nginx overwrites this header on every location that reaches the gate: one it does not overwrite is the client's own, and the audit would write down whatever the client chose to say. A list such as X-Forwarded-For is read from its last entry, which is the one nginx added.",
            "L'header da cui l'audit legge l'indirizzo del client, per esempio X-Real-IP. Vuoto non registra alcun indirizzo. Indicalo solo quando nginx sovrascrive questo header su ogni location che arriva al gate: uno che non sovrascrive è quello del client, e l'audit scriverebbe qualunque cosa il client abbia scelto di dire. Di una lista come X-Forwarded-For si legge l'ultima voce, cioè quella aggiunta da nginx.",
        ),
        K::AuditRotation => m(lang, "Rotation", "Rotazione"),
        K::AuditRotationHelp => m(
            lang,
            "When the live file moves onto the previous one, which it replaces: only the last is kept. A size (MiB, GiB), or an age of the file's oldest event (weeks, months, years).",
            "Quando il file attivo passa al posto del precedente, che sostituisce: si conserva solo l'ultimo. Una dimensione (MiB, GiB), oppure l'età dell'evento più vecchio del file (settimane, mesi, anni).",
        ),
        K::AuditRetention => m(lang, "Retention", "Conservazione"),
        K::AuditRetentionHelp => m(
            lang,
            "The most the audit keeps, across both files. An age: no event older than it stays on disk, which is the one to use for personal data such as addresses. A size: the two files together never exceed it. At least one of rotation and retention must be a size, or a flood of refusals could fill the disk.",
            "Il massimo che l'audit conserva, sommando i due file. Un'età: nessun evento più vecchio resta su disco, ed è quella da usare per dati personali come gli indirizzi. Una dimensione: i due file insieme non la superano mai. Almeno una tra rotazione e conservazione deve essere una dimensione, altrimenti un'ondata di rifiuti potrebbe riempire il disco.",
        ),
        K::AuditOnDisk => m(lang, "At most on disk", "Al massimo su disco"),
        K::LimitNone => m(lang, "none", "nessuna"),
        K::UnitWeek => m(lang, "week", "settimana"),
        K::UnitWeeks => m(lang, "weeks", "settimane"),
        K::UnitMonth => m(lang, "month", "mese"),
        K::UnitMonths => m(lang, "months", "mesi"),
        K::UnitYear => m(lang, "year", "anno"),
        K::UnitYears => m(lang, "years", "anni"),
        K::GroupsExpand => m(lang, "Expand all", "Espandi tutto"),
        K::GroupsCollapse => m(lang, "Collapse all", "Comprimi tutto"),
        K::RequestIdHeader => m(lang, "Request id header", "Header dell'id della richiesta"),
        K::RequestIdHeaderHelp => m(
            lang,
            "The request header carrying nginx's own id for the request, such as X-Request-ID set from $request_id. Empty records none. With $request_id in nginx's log format as well, the id on an audit row finds that request's line in nginx's access log, which has everything the audit leaves out. The same rule holds: nginx must overwrite it.",
            "L'header con l'id che nginx assegna alla richiesta, per esempio X-Request-ID impostato da $request_id. Vuoto non registra nulla. Con $request_id anche nel log_format di nginx, l'id su una riga dell'audit ritrova la riga di quella richiesta nel log di accesso di nginx, che contiene tutto quello che l'audit tralascia. Vale la stessa regola: nginx deve sovrascriverlo.",
        ),
        K::ConfigHot => m(
            lang,
            "Saved here, live on the next request.",
            "Salvato qui, attivo dalla richiesta successiva.",
        ),
        K::ProfileClaims => m(lang, "Profile claims", "Claim di profilo"),
        K::ProfileClaimsHelp => m(
            lang,
            "OIDC claims to hand to the application, one per line. The header is derived from the name and is never configured: given_name becomes X-Auth-Given-Name. They are self-asserted decoration: they authorize nothing.",
            "Claim OIDC da passare all'applicazione, uno per riga. L'header è derivato dal nome e non si configura: given_name diventa X-Auth-Given-Name. Sono decorazione auto-dichiarata: non autorizzano nulla.",
        ),
        K::IdentityAttrs => m(lang, "Identity attributes", "Attributi di identità"),
        K::IdentityAttrsHelp => m(
            lang,
            "What a 204 names the authorized identity with, one per line: email, uuid. Never empty. nginx already clears both names, so turning one on needs no change there.",
            "Con cosa un 204 nomina l'identità autorizzata, uno per riga: email, uuid. Mai vuoto. nginx azzera già entrambi i nomi, quindi accenderne uno non richiede modifiche lì.",
        ),
        K::SessionTtl => m(lang, "Session lifetime", "Durata della sessione"),
        // The list box's own words, not the file's codes: the box shows "Light", "Dark" and
        // the system option in the reader's language, so `light, dark, system` were wire
        // words on a page (§13.31 §10). Only a request this form did not build carries
        // another value, which is what the sentence says.
        K::SessionTtlBad => m(
            lang,
            "{0}: must be a whole number of seconds, such as 2592000 for 30 days.",
            "{0}: deve essere un numero intero di secondi, come 2592000 per 30 giorni.",
        ),
        K::DefaultThemeBad => m(
            lang,
            "{0}: choose one of the options in the list; this request carried a value the \
             list does not offer.",
            "{0}: scegli una delle opzioni dell'elenco; questa richiesta portava un valore \
             che l'elenco non offre.",
        ),
        // A settings-file refusal, in the reader's language (§13.31). `{0}` is the visible label
        // of the field the refusal is marked on, filled by `settings_refusal` through `fill`.
        K::SetRefFileOnly => m(
            lang,
            "The settings file is refused for a reason this page cannot fix: correct it with bb-auth-adm over SSH. The gate says: {0}",
            "Il file delle impostazioni viene rifiutato per un motivo che questa pagina non può risolvere: correggilo con bb-auth-adm via SSH. Il gate dice: {0}",
        ),
        K::SetRefClaimCharset => m(
            lang,
            "{0}: '{1}' may contain only letters, digits, '_', ':' and '-'.",
            "{0}: '{1}' può contenere solo lettere, cifre, '_', ':' e '-'.",
        ),
        K::SetRefClaimEmptyPart => m(
            lang,
            "{0}: '{1}' starts or ends with '_', ':' or '-', or has two of them in a row; each one must sit between letters or digits.",
            "{0}: '{1}' inizia o finisce con '_', ':' o '-', oppure ne ha due di fila; ognuno deve stare tra lettere o cifre.",
        ),
        K::SetRefClaimConsumed => m(
            lang,
            "{0}: '{1}' is a claim the gate reads for itself, so it cannot be passed to the application.",
            "{0}: '{1}' è un claim che il gate legge per sé, quindi non può essere passato all'applicazione.",
        ),
        K::SetRefClaimHeaderReserved => m(
            lang,
            "{0}: '{1}' would become the header {2}, which the gate keeps for itself.",
            "{0}: '{1}' diventerebbe l'header {2}, che il gate riserva a sé.",
        ),
        K::SetRefClaimsCollide => m(
            lang,
            "{0}: '{1}' and '{2}' would both become the header {3}; keep only one of them.",
            "{0}: '{1}' e '{2}' diventerebbero entrambi l'header {3}; tienine solo uno.",
        ),
        K::SetRefAttrUnknown => m(
            lang,
            "{0}: '{1}' is not one of: {2}.",
            "{0}: '{1}' non è uno tra: {2}.",
        ),
        K::SetRefAttrTwice => m(
            lang,
            "{0}: '{1}' is listed twice.",
            "{0}: '{1}' compare due volte.",
        ),
        K::SetRefAttrNone => m(
            lang,
            "{0}: at least one is needed ({1}); without one, the applications behind the gate cannot tell who signed in.",
            "{0}: ne serve almeno uno ({1}); senza, le applicazioni dietro il gate non sanno chi è entrato.",
        ),
        K::SetRefTtlBelowFloor => m(
            lang,
            "{0}: must be at least {1} seconds; a session that expires as it is handed over sends everybody back to the sign-in page.",
            "{0}: servono almeno {1} secondi; una sessione che scade mentre viene consegnata rimanda tutti alla pagina di accesso.",
        ),
        K::SetRefTtlAboveCeiling => m(
            lang,
            "{0}: must be at most {1} seconds.",
            "{0}: può essere al massimo di {1} secondi.",
        ),
        K::SetRefAppClientId => m(
            lang,
            "App client for {0}: '{1}' may contain only letters, digits, '.', '_' and '-'.",
            "App client per {0}: '{1}' può contenere solo lettere, cifre, '.', '_' e '-'.",
        ),
        K::SetRefUrlNotPrintable => m(
            lang,
            "{0}: may contain only plain ASCII characters, with no spaces, accented letters or control characters.",
            "{0}: può contenere solo caratteri ASCII semplici, senza spazi, lettere accentate o caratteri di controllo.",
        ),
        K::SetRefUrlNotHttps => m(
            lang,
            "{0}: must be an absolute address starting with https://.",
            "{0}: deve essere un indirizzo assoluto che inizia con https://.",
        ),
        K::SetRefUrlEmptyHost => m(
            lang,
            "{0}: the address names no host after https://.",
            "{0}: l'indirizzo non indica alcun host dopo https://.",
        ),
        K::SetRefUrlUserinfo => m(
            lang,
            "{0}: a user name and '@' before the host are not allowed.",
            "{0}: un nome utente con '@' prima dell'host non è ammesso.",
        ),
        K::SetRefUrlBackslash => m(
            lang,
            "{0}: a backslash (\\) is not allowed.",
            "{0}: la barra rovesciata (\\) non è ammessa.",
        ),
        K::SetRefUrlUserinfoOrBackslash => m(
            lang,
            "{0}: neither a user name with '@' nor a backslash (\\) is allowed.",
            "{0}: non sono ammessi né un nome utente con '@' né la barra rovesciata (\\).",
        ),
        K::SetRefUrlQueryOrFragment => m(
            lang,
            "{0}: must be the issuer address alone, with no '?' query and no '#' fragment.",
            "{0}: deve essere solo l'indirizzo dell'issuer, senza query '?' né frammento '#'.",
        ),
        K::SetRefUrlQuote => m(
            lang,
            "{0}: quotes and angle brackets are not allowed.",
            "{0}: virgolette e parentesi angolari non sono ammesse.",
        ),
        K::SetRefUrlNotHttpsOrRooted => m(
            lang,
            "{0}: must be an absolute https:// address or a path starting with '/'.",
            "{0}: deve essere un indirizzo https:// assoluto o un percorso che inizia con '/'.",
        ),
        K::SetRefCallbackNotHttps => m(
            lang,
            "{0}: must be the absolute https:// address registered on the app clients, because Cognito compares it byte for byte.",
            "{0}: deve essere l'indirizzo https:// assoluto registrato sugli app client, perché Cognito lo confronta byte per byte.",
        ),
        K::SetRefCookieDomainNotBare => m(
            lang,
            "{0}: must be a bare domain such as .example.com: letters, digits, '.' and '-', with no scheme, port or path.",
            "{0}: deve essere un dominio puro come .example.com: lettere, cifre, '.' e '-', senza schema, porta o percorso.",
        ),
        K::SetRefCookieDomainSingleLabel => m(
            lang,
            "{0}: no browser keeps a cookie for a one-word domain; name the domain the services share, such as .example.com.",
            "{0}: nessun browser conserva un cookie per un dominio di una sola parola; indica il dominio che i servizi hanno in comune, come .example.com.",
        ),
        K::SetRefHostControlByte => m(
            lang,
            "{0}: '{1}' contains a control character, often left by a paste; type it again.",
            "{0}: '{1}' contiene un carattere di controllo, spesso lasciato da un copia e incolla; riscrivilo.",
        ),
        K::SetRefHostNotBare => m(
            lang,
            "{0}: '{1}' must be a bare host such as app.example.com, with no scheme, port or path.",
            "{0}: '{1}' deve essere un host puro come app.example.com, senza schema, porta o percorso.",
        ),
        K::SetRefHostAtOrDotDot => m(
            lang,
            "{0}: '{1}' must not contain '@' or '..'.",
            "{0}: '{1}' non deve contenere '@' o '..'.",
        ),
        K::SetRefHostsOutsideCookieDomain => m(
            lang,
            "{0}: the {2} '{3}' does not reach {1}, so a sign-in that lands there carries no session cookie and loops back to the sign-in page.",
            "{0}: il {2} '{3}' non raggiunge {1}, quindi un accesso che arriva lì non porta il cookie di sessione e torna in ciclo alla pagina di accesso.",
        ),
        K::SetRefLandingOffHosts => m(
            lang,
            "{0}: must be on one of the {1}, or every sign-in that names no page falls back to the sign-in page.",
            "{0}: deve stare su uno degli {1}, altrimenti ogni accesso che non indica una pagina ricade sulla pagina di accesso.",
        ),
        K::SetRefOauthDomainNotBare => m(
            lang,
            "{0}: must be a bare host: letters, digits, '.' and '-', with no scheme and no path.",
            "{0}: deve essere un host puro: lettere, cifre, '.' e '-', senza schema né percorso.",
        ),
        K::SetRefHeaderNotAName => m(
            lang,
            "{0}: '{1}' is not a header name: letters, digits and '-' only (nginx drops a header with an underscore in its name).",
            "{0}: '{1}' non è un nome di header: solo lettere, cifre e '-' (nginx scarta un header con un trattino basso nel nome).",
        ),
        K::SetRefHeaderCredential => m(
            lang,
            "{0}: '{1}' carries a credential, and the audit never writes one down.",
            "{0}: '{1}' contiene una credenziale, e l'audit non registra mai credenziali.",
        ),
        K::SetRefHeadersSame => m(
            lang,
            "{0}: '{1}' is already the {2}; one header cannot carry both an address and a request id.",
            "{0}: '{1}' è già l'{2}; un solo header non può portare sia un indirizzo sia un id di richiesta.",
        ),
        K::SetRefLimitNotAmount => m(
            lang,
            "{0}: the amount must be a whole number.",
            "{0}: la quantità deve essere un numero intero.",
        ),
        K::SetRefLimitZero => m(
            lang,
            "{0}: the amount must be more than 0.",
            "{0}: la quantità deve essere maggiore di 0.",
        ),
        K::SetRefLimitTooMuch => m(
            lang,
            "{0}: the most allowed is {1} {2}.",
            "{0}: il massimo ammesso è {1} {2}.",
        ),
        K::SetRefAuditUnbounded => m(
            lang,
            "{0} and {1}: at least one of the two must be a size (MiB, GiB), or a flood of refusals would grow the audit without limit.",
            "{0} e {1}: almeno una delle due deve essere una dimensione (MiB, GiB), altrimenti un'ondata di rifiuti farebbe crescere l'audit senza limite.",
        ),
        K::SetRefBrandControl => m(
            lang,
            "{0}: control characters are not allowed.",
            "{0}: i caratteri di controllo non sono ammessi.",
        ),
        K::SetRefBrandTooLong => m(
            lang,
            "{0}: {1} characters, and at most {2} are allowed.",
            "{0}: {1} caratteri, e ne sono ammessi al massimo {2}.",
        ),
        // The page's own two, in the same register: the label, then what is needed. The
        // library cannot raise them, because it does not know who is signed in.
        K::SetRefAdminsNone => m(
            lang,
            "{0}: at least one is needed; an empty list must never come to mean 'everyone'.",
            "{0}: ne serve almeno uno; una lista vuota non deve mai finire per significare \
             'chiunque'.",
        ),
        K::SetRefAdminsSelf => m(
            lang,
            "{0}: your own address must stay on the list; to remove yourself, use \
             bb-auth-adm over SSH.",
            "{0}: il tuo indirizzo deve restare nella lista; per rimuovere te stesso usa \
             bb-auth-adm via SSH.",
        ),
        K::SessionTtlHelp => m(
            lang,
            "Seconds. Applies to cookies minted from now on: nobody is logged out by changing it.",
            "Secondi. Vale per i cookie coniati da adesso: cambiarla non disconnette nessuno.",
        ),
        K::UnverifiedSocial => m(
            lang,
            "Accept unverified social emails",
            "Accetta email social non verificate",
        ),
        K::UnverifiedSocialHelp => m(
            lang,
            "Only for federated logins (Google, Apple…), never for native Cognito users, whose sign-up is open and whose unverified email is attacker-controlled.",
            "Solo per accessi federati (Google, Apple…), mai per utenti Cognito nativi: la loro registrazione è aperta e un'email non verificata è controllata da chi attacca.",
        ),

        K::GlobalLoginUrl => m(lang, "Sign-in page", "Pagina di accesso"),
        K::GlobalLoginUrlHelp => m(
            lang,
            "Where a 401 sends people, and where a rejected redirect lands. Empty means the gate's own /auth/login on the host the request arrived at, which is what a deployment that has not moved its sign-in page wants. An application can override it for its own area.",
            "Dove un 401 manda le persone, e dove finisce un redirect rifiutato. Vuoto significa la /auth/login del gate stesso sull'host da cui arriva la richiesta, che è quello che vuole un deployment che non ha spostato la propria pagina di accesso. Una applicazione può sovrascriverla per la propria area.",
        ),
        K::GlobalDeniedUrl => m(lang, "Refusal page", "Pagina di rifiuto"),
        K::GlobalDeniedUrlHelp => m(
            lang,
            "Where a 403 sends people: somebody who is signed in and is not admitted here. Empty means the gate's own /auth/denied, which it builds out of the look below. It cannot shut a door, only decide what the person already shut out is shown. An application can override it for its own area, which is how one gate gives each host its own page.",
            "Dove un 403 manda le persone: qualcuno che ha fatto l'accesso e qui non è ammesso. Vuoto significa la /auth/denied del gate stesso, costruita con l'aspetto qui sotto. Non può chiudere nessuna porta: decide solo cosa vede chi è già stato respinto. Una applicazione può sovrascriverla per la propria area, ed è così che un solo gate dà a ogni host la sua pagina.",
        ),
        K::GlobalLandingUrl => m(lang, "Landing page", "Pagina di arrivo"),
        K::GlobalLandingUrlHelp => m(
            lang,
            "Where a sign-in lands when nothing named a place. Empty means the caller's root. It must be on one of the authorized hosts, or every sign-in falls back to the sign-in page.",
            "Dove arriva un accesso quando nessuno ha indicato una pagina. Vuoto significa la radice del chiamante. Deve stare su uno degli host autorizzati, altrimenti ogni accesso ricade sulla pagina di accesso.",
        ),
        K::OauthDomain => m(lang, "Hosted UI domain", "Dominio della hosted UI"),
        K::OauthDomainHelp => m(
            lang,
            "Cognito's hosted UI for this pool, as a bare host: no scheme, no path. Empty means this deployment offers no social sign-in at all, whatever the table below says.",
            "La hosted UI Cognito di questo pool, come host puro: niente schema, niente percorso. Vuoto significa nessun accesso social, qualunque cosa dica la tabella sotto.",
        ),
        K::SocialCallback => m(lang, "Callback URL", "URL di callback"),
        K::SocialCallbackHelp => m(
            lang,
            "Where Cognito sends the browser back, normally /auth/callback on the host that serves the sign-in page. It must be registered byte for byte on every app client in the table, or Amazon answers redirect_mismatch on Amazon's page.",
            "Dove Cognito rimanda il browser, di norma /auth/callback sull'host che serve la pagina di accesso. Deve essere registrato byte per byte su ogni app client della tabella, altrimenti Amazon risponde redirect_mismatch sulla propria pagina.",
        ),
        K::SignInWays => m(lang, "Ways in", "Modi di accesso"),
        K::SignInEmail => m(lang, "Email and code", "Email e codice"),
        K::ClientIdNeeded => m(
            lang,
            "App client for {0}: cannot be empty; without one, no sign-in can complete. It \
             is the Cognito app client the sign-in page signs people in against.",
            "App client per {0}: non può essere vuoto; senza, nessun accesso può \
             concludersi. È l'app client Cognito con cui la pagina di accesso fa entrare le \
             persone.",
        ),
        K::AudienceNeeded => m(
            lang,
            "App client for {0}: this provider needs its own, because Cognito federates per \
             app client; name the one that offers this provider.",
            "App client per {0}: questo provider ha bisogno del proprio, perché Cognito \
             federa per app client; indica quello che offre questo provider.",
        ),
        K::SocialWiringNeeded => m(
            lang,
            "{0} and {1}: a social button needs both; without them there is nowhere to send \
             a visitor and nowhere for them to come back to.",
            "{0} e {1}: un pulsante social ha bisogno di entrambi; senza, non c'è dove \
             mandare chi entra né dove farlo tornare.",
        ),
        K::SocialWaysHelp => m(
            lang,
            "Every way into this deployment, and the Cognito app client it runs through. \
             Email and code is always offered and is the app client the sign-in page runs \
             USER_AUTH against; each social provider is offered only if it is ticked, and \
             carries its own app client, because Cognito federates per app client. These app \
             clients ARE the audiences the gate accepts: an id_token carries the client it \
             was minted for. They all belong to the User pool (issuer) above. Microsoft is \
             the personal account (outlook.com, hotmail.com), not a work or school one: an \
             Entra ID tenant is a separate provider on the pool.",
            "Ogni modo di entrare in questo deployment, e l'app client Cognito attraverso cui \
             passa. Email e codice è sempre offerto ed è l'app client con cui la pagina di \
             accesso esegue USER_AUTH; ogni provider social viene offerto solo se è spuntato \
             e porta il proprio app client, perché Cognito federa per app client. Questi app \
             client SONO le audience che il gate accetta: un id_token porta il client per cui \
             è stato emesso. Appartengono tutti allo User pool (issuer) qui sopra. Microsoft \
             è l'account personale (outlook.com, hotmail.com), non uno aziendale o \
             scolastico: un tenant Entra ID è un provider separato sul pool.",
        ),
        K::ColShownAs => m(lang, "shown as", "mostrato come"),
        K::ColAudience => m(lang, "app client (aud)", "app client (aud)"),
        K::SocialProviders => m(lang, "Providers", "Provider"),
        K::SocialProvidersHelp => m(
            lang,
            "One per line, matched against the token's providerName. Empty means any federated provider.",
            "Uno per riga, confrontati con il providerName del token. Vuoto significa qualsiasi provider federato.",
        ),
        K::Issuer => m(lang, "User pool (issuer)", "User pool (issuer)"),
        K::IssuerHelp => m(
            lang,
            "The Cognito user pool this deployment trusts: every id_token is checked against \
             its iss and signed by its keys. It is also the one pool the app clients below \
             can belong to.",
            "Lo user pool Cognito di cui questo deployment si fida: ogni id_token viene \
             verificato contro il suo iss ed è firmato dalle sue chiavi. È anche l'unico pool \
             a cui gli app client qui sotto possono appartenere.",
        ),
        K::IssuerNeeded => m(
            lang,
            "{0}: cannot be empty; without one, no token can be validated and no sign-in \
             can complete.",
            "{0}: non può essere vuoto; senza, nessun token può essere validato e nessun \
             accesso può concludersi.",
        ),
        K::CookieDomain => m(lang, "Cookie domain", "Dominio del cookie"),
        K::CookieDomainHelp => m(
            lang,
            "The domain the session cookie is sent to, such as .example.com, which is what \
             makes one login cover every service behind the gate. Empty binds the session to \
             a single host. Changing it does not sign anybody out: it does something worse, \
             so this page asks first.",
            "Il dominio a cui viene inviato il cookie di sessione, ad esempio .example.com, \
             che è ciò che fa valere un solo accesso per tutti i servizi dietro il gate. \
             Vuoto lega la sessione a un host solo. Cambiarlo non disconnette nessuno: fa \
             qualcosa di peggio, quindi questa pagina chiede prima.",
        ),
        K::AuthorizedHosts => m(lang, "Authorized hosts", "Host autorizzati"),
        K::AuthorizedHostsHelp => m(
            lang,
            "One host per line, the only places a browser may be sent after signing in. \
             Wildcards are allowed (*.example.com), and the apex has to be listed on its own \
             because *.example.com does not match example.com. Every one of them must be \
             reachable by the cookie domain above.",
            "Un host per riga, gli unici posti in cui un browser può essere mandato dopo \
             l'accesso. I wildcard sono ammessi (*.example.com) e il dominio nudo va elencato \
             a parte, perché *.example.com non corrisponde a example.com. Ognuno deve essere \
             raggiungibile dal dominio del cookie qui sopra.",
        ),
        K::AuthorizedHostsNeeded => m(
            lang,
            "{0}: at least one is needed; without one, every redirect after sign-in is \
             refused and everybody lands back on the sign-in page.",
            "{0}: ne serve almeno uno; senza, ogni redirect dopo l'accesso viene rifiutato e \
             tutti tornano alla pagina di accesso.",
        ),
        K::ConfirmTitle => m(
            lang,
            "This can stop people getting in",
            "Questa modifica può impedire l'accesso",
        ),
        K::ConfirmLede => m(
            lang,
            "Nothing has been saved. Read what each change costs, then confirm it, or go back \
             and edit the value below.",
            "Non è stato salvato niente. Leggi che cosa comporta ogni modifica, poi confermala \
             oppure torna sul campo qui sotto e correggilo.",
        ),
        K::ConfirmSafety => m(
            lang,
            "None of this invalidates a session cookie, so your own login survives the change \
             and you can put it back. If it does not, bb-auth-adm over SSH is the way back.",
            "Niente di tutto questo invalida un cookie di sessione, quindi il tuo accesso \
             sopravvive alla modifica e puoi rimetterla com'era. Se non bastasse, la via di \
             ritorno è bb-auth-adm via SSH.",
        ),
        K::ConfirmSave => m(lang, "Confirm and save", "Conferma e salva"),
        K::ColSetting => m(lang, "setting", "impostazione"),
        K::ColNow => m(lang, "now", "adesso"),
        K::ColAfter => m(lang, "after saving", "dopo il salvataggio"),
        K::RiskIssuer => m(
            lang,
            "Every id_token is checked against this pool's iss and its signing keys. Point it \
             at the wrong pool and no login completes. On reload the gate fetches the new \
             pool's keys first, and keeps the old pool if they do not answer.",
            "Ogni id_token viene verificato contro l'iss di questo pool e le sue chiavi di \
             firma. Puntalo al pool sbagliato e nessun accesso si conclude. Al reload il gate \
             scarica prima le chiavi del nuovo pool, e se non rispondono tiene il vecchio.",
        ),
        K::RiskClientId => m(
            lang,
            "The app client the email sign-in runs through, and one of the audiences a token \
             is accepted for. Wrong, and every id_token is refused for its aud.",
            "L'app client con cui gira l'accesso via email, e una delle audience per cui un \
             token viene accettato. Sbagliato, e ogni id_token viene rifiutato per il suo aud.",
        ),
        K::RiskLoginUrl => m(
            lang,
            "Where a 401 sends a browser. Wrong, and everybody who is not signed in lands on \
             a page that is not there.",
            "Dove un 401 manda il browser. Sbagliato, e chiunque non abbia una sessione \
             finisce su una pagina che non esiste.",
        ),
        K::RiskCookieDomain => m(
            lang,
            "This one does something worse than shut a door. Every session cookie already \
             issued keeps the OLD domain, so it stays valid until it expires and the logout \
             can no longer clear it: a logout that silently succeeds at nothing, for everybody \
             who signed in before this save. Putting the old value back makes those cookies \
             clearable again.",
            "Questa fa qualcosa di peggio che chiudere una porta. Ogni cookie di sessione già \
             emesso conserva il dominio VECCHIO, quindi resta valido fino alla scadenza e il \
             logout non riesce più a cancellarlo: un logout che riesce in silenzio senza fare \
             niente, per chiunque abbia fatto accesso prima di questo salvataggio. Rimettere \
             il valore di prima rende di nuovo cancellabili quei cookie.",
        ),
        K::RiskAuthorizedHosts => m(
            lang,
            "A host taken off this list can no longer be redirected to after a login, so \
             anyone signing in for it lands back on the sign-in page instead. Adding one is \
             not asked about; only removing is.",
            "Un host tolto da questa lista non può più essere la destinazione dopo un \
             accesso, quindi chi entra per quell'host torna alla pagina di accesso. \
             Aggiungerne uno non viene chiesto; solo toglierne.",
        ),
        K::Admins => m(lang, "Administrators", "Amministratori"),
        K::AdminsHelp => m(
            lang,
            "One email per line. These are the only people this interface opens for, on top of the gate that already stands in front of it.",
            "Un'email per riga. Sono le uniche persone per cui questa interfaccia si apre, oltre al gate che le sta già davanti.",
        ),
        K::AdminsKeepYourself => m(
            lang,
            "you cannot remove yourself here: do it from bb-auth-adm, over SSH",
            "non puoi rimuovere te stesso da qui: fallo da bb-auth-adm, via SSH",
        ),
        K::AdminsNeverEmpty => m(
            lang,
            "at least one administrator is required: an empty list must never come to mean 'everyone'",
            "serve almeno un amministratore: una lista vuota non deve mai finire per significare 'chiunque'",
        ),
        K::StylesheetUrl => m(lang, "Stylesheet", "Foglio di stile"),
        K::StylesheetUrlHelp => m(
            lang,
            "A stylesheet loaded after the built-in one, on this interface and on the gate's \
             own pages: an absolute https:// URL, or a path starting with / on this host. It \
             is expected to redefine the theme's custom properties and nothing else. Leave it \
             empty and the built-in look is the whole answer; a URL that does not answer costs \
             the page its palette and nothing more.",
            "Un foglio di stile caricato dopo quello incorporato, su questa interfaccia e \
             sulle pagine del gate: un URL https:// assoluto, oppure un percorso che inizia \
             con / su questo host. Deve ridefinire le custom property del tema e nient'altro. \
             Lascialo vuoto e vale l'aspetto incorporato; un URL che non risponde costa alla \
             pagina la sua palette e nulla di più.",
        ),
        K::LogoUrl => m(lang, "Logo", "Logo"),
        K::LogoUrlHelp => m(
            lang,
            "Shown on the gate's login page, above the name. Same two shapes as the \
             stylesheet. Empty means the name alone.",
            "Mostrato sulla pagina di accesso del gate, sopra il nome. Stesse due forme del \
             foglio di stile. Vuoto significa solo il nome.",
        ),
        K::BrandName => m(lang, "Name", "Nome"),
        K::BrandNameHelp => m(
            lang,
            "What the login page calls this deployment. Empty and each page falls back to its \
             own name.",
            "Come la pagina di accesso chiama questo deployment. Vuoto e ogni pagina ripiega \
             sul proprio nome.",
        ),
        K::DefaultTheme => m(lang, "Default appearance", "Aspetto predefinito"),
        K::DefaultThemeHelp => m(
            lang,
            "Which palette a page starts in for someone who has chosen nothing. The gate's \
             pages have nowhere to keep a choice, so for them this is the whole answer; here \
             it is only the default, and the Settings menu above still overrides it in your \
             own browser.",
            "Con quale palette parte una pagina per chi non ha scelto nulla. Le pagine del \
             gate non hanno dove tenere una scelta, quindi per loro è tutta la risposta; qui \
             è solo il valore predefinito, e il menu Impostazioni qui sopra continua a \
             prevalere nel tuo browser.",
        ),
        K::Days => m(lang, "days", "giorni"),
        K::MsgSettingsSaved => m(lang, "settings saved", "impostazioni salvate"),
        K::Groups => m(lang, "User groups", "Gruppi di utenti"),
        K::Apps => m(lang, "Applications", "Applicazioni"),
        K::Scopes => m(lang, "Scopes", "Ambiti"),
        K::MembersHeading => m(lang, "Members", "Membri"),
        K::Users => m(lang, "Users", "Utenti"),
        K::People => m(lang, "People", "Persone"),
        K::GroupsTab => m(lang, "Groups", "Gruppi"),
        K::UsersSections => m(lang, "Users sections", "Sezioni di Utenti"),
        K::Denied => m(lang, "Denied", "Bloccati"),
        K::Can => m(lang, "Access check", "Verifica accesso"),
        K::Back => m(lang, "back", "indietro"),
        K::None => m(lang, "none", "nessuno"),
        K::Counts => m(lang, "What is in the file", "Cosa c'è nel file"),
        K::KeyExpiry => m(lang, "Key expiry", "Scadenza delle chiavi"),
        K::ColOwner => m(lang, "owner", "proprietario"),
        K::ColExpiry => m(lang, "expiry", "scadenza"),
        K::Expired => m(lang, "expired", "scaduta"),
        K::ExpiresSoon => m(lang, "expires soon", "scade a breve"),
        K::NeverExpires => m(lang, "never expires", "non scade mai"),
        K::KeyInvalid => m(
            lang,
            "invalid released/duration — the gate skips this key",
            "released/duration non validi — il gate salta questa chiave",
        ),
        K::Expires => m(lang, "expires", "scade il"),
        K::Warnings => m(lang, "Warnings", "Avvisi"),
        K::NoWarnings => m(lang, "nothing to report", "nulla da segnalare"),
        K::KindScope => m(lang, "Scope", "Scope"),
        K::KindUser => m(lang, "User", "Utente"),
        K::KindGroup => m(lang, "User group", "Gruppo di utenti"),
        K::WarnNoScope => m(
            lang,
            "reaches nothing: no scope lists them",
            "non raggiunge nulla: nessuno scope lo elenca",
        ),
        K::WarnEnrolledAndDenied => m(
            lang,
            "is in users and in denied — denied wins, on every credential",
            "è in users e in denied — vince denied, su ogni credenziale",
        ),
        K::ReferencedBy => m(lang, "referenced by", "referenziato da"),
        K::ReferencedByNothing => m(lang, "referenced by nothing", "referenziato da nulla"),
        K::Base => m(lang, "base", "base"),
        K::Members => m(lang, "members", "membri"),
        K::Uuid => m(lang, "uuid", "uuid"),
        K::Emails => m(lang, "emails", "email"),
        K::ColGroups => m(lang, "groups", "gruppi"),
        K::GroupInRoster => m(lang, "show them in People", "mostrali in Persone"),
        K::GroupFilter => m(lang, "group: {0}", "gruppo: {0}"),
        K::GroupFilterClear => m(lang, "show every group", "mostra tutti i gruppi"),
        K::AccessWord => m(lang, "access", "accesso"),
        K::Credentials => m(lang, "credentials", "credenziali"),
        K::LoginUrl => m(lang, "login_url", "login_url"),
        K::DeniedUrl => m(lang, "denied_url", "denied_url"),
        K::CredLogin => m(lang, "login", "login"),
        K::CredApiKey => m(lang, "api_key", "api_key"),
        K::AccessAnonymous => m(lang, "anonymous", "anonimo"),
        K::AccessAuthenticated => m(lang, "authenticated", "autenticato"),
        K::AccessRestricted => m(lang, "restricted", "ristretto"),
        K::NoScopes => m(lang, "no scopes", "nessuno scope"),
        K::AddEmail => m(lang, "Add an email", "Aggiungi un\u{2019}email"),
        K::InNoScope => m(
            lang,
            "in no scope: this user reaches nothing",
            "in nessuno scope: questo utente non raggiunge nulla",
        ),
        K::ReachesNothing => m(lang, "reaches nothing", "non raggiunge nulla"),
        K::NoSuchUser => m(lang, "no such user", "utente inesistente"),
        K::UsersIntro => m(
            lang,
            "The roster: an identity, the emails that resolve to it, and its keys. What a \
             user reaches is written on the side of the place, in the scopes that list them.",
            "Il roster: un\u{2019}identità, le email che vi si risolvono e le sue chiavi. Ciò \
             che un utente raggiunge è scritto dalla parte del posto, negli scope che lo \
             elencano.",
        ),
        K::GroupsIntro => m(
            lang,
            "Named sets of people. A group is abbreviation, never a grant: defining one \
             authorizes nobody until a scope names it.",
            "Insiemi di persone con un nome. Un gruppo è un\u{2019}abbreviazione, mai una \
             concessione: definirne uno non autorizza nessuno finché uno scope non lo nomina.",
        ),
        K::AppsIntro => m(
            lang,
            "The places, and who reaches them. Every grant in the file is written here. \
             Applications partition the URL space: no two areas overlap, and a URL no \
             application covers is reachable by nobody.",
            "I posti, e chi li raggiunge. Ogni concessione del file è scritta qui. Le \
             applicazioni partizionano lo spazio degli URL: due aree non si sovrappongono \
             mai, e un URL che nessuna applicazione copre non è raggiungibile da nessuno.",
        ),
        K::ScopesIntro => m(
            lang,
            "In file order, and the order is the meaning: first match wins, so the first \
             scope whose urls cover a request answers for it, even if it grants nothing. \
             Put the narrow, stricter scope first.",
            "Nell\u{2019}ordine del file, e l\u{2019}ordine è il significato: vince la prima \
             corrispondenza, quindi risponde il primo scope le cui urls coprono la richiesta, \
             anche se non concede nulla. Lo scope stretto e severo va prima.",
        ),
        K::DeniedIntro => m(
            lang,
            "A veto. It outranks every grant, on every credential, and it is not the same as \
             deleting the user\u{2019}s row. An enrolled user is vetoed by uuid, so every \
             email they hold goes with it; a stranger is vetoed by the email itself.",
            "Un veto. Batte ogni concessione, su ogni credenziale, e non equivale a cancellare \
             la riga dell\u{2019}utente. Un utente iscritto si veta per uuid, quindi ci vanno \
             dietro tutte le sue email; uno sconosciuto si veta con l\u{2019}email stessa.",
        ),
        K::CanIntroUser => m(
            lang,
            "Would this person reach a URL? Answered by the gate's own decision function, on \
             the file as it is on disk right now.",
            "Questa persona raggiungerebbe un URL? Risponde la funzione di decisione del gate, \
             sul file così com'è su disco adesso.",
        ),
        // Only worth saying where there is more than one address to wonder about, which is why
        // it is a sentence of its own rather than part of the one above.
        K::CanAnyEmail => m(
            lang,
            "Any of the emails above gives the same answer: each one resolves to this row.",
            "Ognuna delle email qui sopra dà la stessa risposta: ciascuna risolve a questa \
             riga.",
        ),
        K::CanIntroApp => m(
            lang,
            "Would this credential reach this URL? Answered by the gate's own decision \
             function, on the file as it is on disk right now, and it names the scope that \
             answered. Leave the email empty to ask what a client with no credential at all \
             reaches.",
            "Questa credenziale raggiungerebbe questo URL? Risponde la funzione di decisione \
             del gate, sul file così com'è su disco adesso, e nomina lo scope che ha risposto. \
             Lascia l'email vuota per chiedere cosa raggiunge un client senza alcuna \
             credenziale.",
        ),
        K::CanNoIdentifier => m(
            lang,
            "This row has no email, so no credential can ever resolve to it and there is \
             nothing to check. Add one above.",
            "Questa riga non ha email, quindi nessuna credenziale può risolversi a essa e non \
             c'è nulla da verificare. Aggiungine una qui sopra.",
        ),
        K::Submit => m(lang, "Check", "Verifica"),
        K::Authorized => m(lang, "AUTHORIZED", "AUTORIZZATO"),
        K::VerdictDenied => m(lang, "DENIED", "NEGATO"),
        K::WhyAnonymousGrant => m(
            lang,
            "is anonymous: it grants with no credential at all, so this URL is open to \
             everyone and the 204 names nobody.",
            "è anonimo: concede senza alcuna credenziale, quindi questo URL è aperto a tutti \
             e il 204 non nomina nessuno.",
        ),
        K::WhyGranted => m(
            lang,
            "admits this credential.",
            "ammette questa credenziale.",
        ),
        K::WhyVetoed => m(
            lang,
            "is on the denied list, which outranks every grant.",
            "è nella lista denied, che batte ogni concessione.",
        ),
        K::WhyExcluded => m(
            lang,
            "is excluded by the scope that answered, ahead of its own grant. This is local: \
             another scope may still admit them.",
            "è escluso dallo scope che ha risposto, prima della sua stessa concessione. È \
             locale: un altro scope può comunque ammetterlo.",
        ),
        K::WhyNoApplication => m(
            lang,
            "is inside no application\u{2019}s area, so nobody reaches it, with any credential.",
            "non è dentro l\u{2019}area di nessuna applicazione, quindi non lo raggiunge \
             nessuno, con nessuna credenziale.",
        ),
        K::WhyNoScope => m(
            lang,
            "owns this URL but has no scope covering it.",
            "possiede questo URL ma non ha uno scope che lo copra.",
        ),
        K::WhyUnauthenticated => m(
            lang,
            "wants an identity, and the request carried no credential.",
            "vuole un\u{2019}identità, e la richiesta non portava credenziali.",
        ),
        K::WhyCredentialRefused => m(
            lang,
            "does not admit this class of credential.",
            "non ammette questa classe di credenziale.",
        ),
        K::WhyNotEnrolled => m(
            lang,
            "is in no users entry, and this scope admits only the people it lists.",
            "non è in nessuna voce users, e questo scope ammette solo le persone che elenca.",
        ),
        K::WhyNotMember => m(
            lang,
            "does not list this user.",
            "non elenca questo utente.",
        ),
        K::WhyKeyOutOfScope => m(
            lang,
            "is not among the scopes this key restricted itself to.",
            "non è tra gli scope a cui questa chiave si è ristretta.",
        ),
        // The refusals that happen before any scope is consulted, or on a path the access
        // check cannot walk. They read as the continuation of a sentence the row starts, the
        // same way the eleven above do.
        K::WhyTokenInvalid => m(
            lang,
            "the token did not validate: wrong pool, wrong app client, expired, or an unverified email.",
            "il token non è stato validato: pool errato, app client errato, scaduto, o email non verificata.",
        ),
        K::WhyCrossSite => m(
            lang,
            "the sign-in did not come from a page of this estate.",
            "l'accesso non proveniva da una pagina di questo dominio.",
        ),
        K::WhyKeyUnknown => m(
            lang,
            "no key in the file has this value. The key itself is never recorded, so there is nothing to name.",
            "nessuna chiave nel file ha questo valore. La chiave non viene mai registrata, quindi non c'è nulla da nominare.",
        ),
        K::WhyKeyExpired => m(lang, "the key has expired.", "la chiave è scaduta."),
        K::WhyKeyOwnerDenied => m(
            lang,
            "the key is valid, and its owner is on the denied list.",
            "la chiave è valida, e il suo proprietario è nella lista dei negati.",
        ),
        K::WhyUnEnrolledGrant => m(
            lang,
            "let in by an authenticated scope, while being in no users entry.",
            "ammesso da uno scope authenticated, pur non essendo in nessuna voce users.",
        ),
        K::WhyUnknownReason => m(
            lang,
            "recorded by a newer version of bb-auth than this one.",
            "registrato da una versione di bb-auth più recente di questa.",
        ),
        // --- the audit ---
        K::Audit => m(lang, "Audit", "Audit"),
        K::AuditIntro => m(
            lang,
            "What the gate has answered: sign-ins, sign-outs and refusals, newest first. Ordinary allowed requests are not here and never were: they are nginx's access log, and one row per asset would bury everything on this page.",
            "Cosa ha risposto il gate: accessi, uscite e rifiuti, dal più recente. Le richieste ordinarie ammesse non ci sono e non ci sono mai state: sono nel log di nginx, e una riga per ogni asset seppellirebbe tutto il resto di questa pagina.",
        ),
        K::AuditOff => m(lang, "The audit is off", "L'audit è disattivato"),
        K::AuditOffHelp => m(
            lang,
            "BB_AUTH_AUDIT_FILE is empty in this service's env file, or names a file the gate does not write. With no file there is nothing to show: the events are in the journal instead, on the host.",
            "BB_AUTH_AUDIT_FILE è vuoto nel file di environment di questo servizio, oppure indica un file che il gate non scrive. Senza file non c'è nulla da mostrare: gli eventi sono nel journal, sull'host.",
        ),
        K::AuditRefresh => m(lang, "Refresh", "Aggiorna"),
        K::AuditWindow => m(lang, "Period", "Periodo"),
        K::AuditAll => m(lang, "Everything", "Tutto"),
        K::AuditOutcome => m(lang, "Outcome", "Esito"),
        K::AuditAny => m(lang, "Any", "Qualsiasi"),
        K::AuditAllowed => m(lang, "Allowed", "Ammesso"),
        K::AuditRefused => m(lang, "Refused", "Rifiutato"),
        K::AuditCredential => m(lang, "Credential", "Credenziale"),
        K::AuditDamaged => m(
            lang,
            "lines could not be read and were skipped.",
            "righe non sono leggibili e sono state saltate.",
        ),
        K::AuditTruncated => m(
            lang,
            "There are older events in this period than this page can hold. Narrow the period to see them.",
            "In questo periodo ci sono eventi più vecchi di quanti questa pagina possa contenerne. Restringi il periodo per vederli.",
        ),
        K::AuditDeduped => m(
            lang,
            "A refusal repeated within five minutes is recorded once: a browser refused one asset is a browser refused forty. Sign-ins and sign-outs are never collapsed.",
            "Un rifiuto ripetuto entro cinque minuti è registrato una volta sola: un browser a cui viene rifiutato un asset è un browser a cui ne vengono rifiutati quaranta. Accessi e uscite non vengono mai accorpati.",
        ),
        // The zone the times are in follows it in brackets, because it is the reader's choice
        // now and a heading that said "UTC" on its own would be wrong half the time.
        K::ColWhen => m(lang, "When", "Quando"),
        K::ColEvent => m(lang, "Event", "Evento"),
        K::ColWho => m(lang, "Who", "Chi"),
        K::ColClient => m(lang, "Client", "Client"),
        K::AuditZone => m(lang, "Time zone", "Fuso orario"),
        K::TzLocal => m(lang, "Local", "Locale"),
        K::TzCustom => m(lang, "Custom", "Personalizzato"),
        K::TzCustomHint => m(lang, "Europe/Rome or +02:00", "Europe/Rome o +02:00"),
        K::TzUnknown => m(
            lang,
            "is not a time zone this server knows, so the times below are in UTC.",
            "non è un fuso orario che questo server conosca: gli orari qui sotto sono in UTC.",
        ),
        K::TzLocalMissing => m(
            lang,
            "This server does not say which time zone it is in, so the times below are in UTC.",
            "Questo server non dice in quale fuso orario si trova: gli orari qui sotto sono in UTC.",
        ),
        K::ColWhere => m(lang, "Where", "Dove"),
        K::ColWhy => m(lang, "Why", "Perché"),
        K::KindLoginGranted => m(lang, "Signed in", "Accesso"),
        K::KindLoginRefused => m(lang, "Sign-in refused", "Accesso rifiutato"),
        K::KindLoginEnded => m(lang, "Signed out", "Uscita"),
        K::KindAccessGranted => m(lang, "Let in", "Ammesso"),
        K::KindAccessRefused => m(lang, "Refused", "Rifiutato"),
        K::CredSocial => m(lang, "Social", "Social"),
        K::CredLocal => m(lang, "Cognito account", "Account Cognito"),
        K::CredKey => m(lang, "API key", "Chiave API"),
        K::CredSession => m(lang, "Session", "Sessione"),
        K::CredAnonymous => m(lang, "None", "Nessuna"),
        K::AppSees => m(lang, "the application sees", "l'applicazione vede"),
        K::NoProxyTitle => m(
            lang,
            "Not through the proxy",
            "Non arriva dal proxy",
        ),
        K::NoProxyBody => m(
            lang,
            "this request did not carry the proxy secret, so it did not arrive through nginx. \
             The admin interface answers only through the proxy that sets it (README, \"The \
             admin GUI behind the gate\").",
            "questa richiesta non porta il secret del proxy, quindi non arriva da nginx. \
             L'interfaccia di amministrazione risponde solo attraverso il proxy che lo imposta \
             (README, \"The admin GUI behind the gate\").",
        ),
        K::NoIdentityTitle => m(lang, "No identity header", "Nessun header di identità"),
        K::NoIdentityBody => m(
            lang,
            "identity header missing — is nginx auth_request wiring in front of this service?",
            "header di identità mancante — c'è il wiring nginx auth_request davanti a questo \
             servizio?",
        ),
        K::NotAdminTitle => m(lang, "Not an administrator", "Non sei un amministratore"),
        K::NotAdminBody => m(
            lang,
            "is authenticated, but is not an administrator of this interface.",
            "è autenticato, ma non è amministratore di questa interfaccia.",
        ),
        K::NotAdminToAccount => m(lang, "Go to your account", "Vai al tuo account"),
        K::NotFoundTitle => m(lang, "Not found", "Non trovato"),
        K::NotFoundBody => m(
            lang,
            "there is no page at this address.",
            "non c'è nessuna pagina a questo indirizzo.",
        ),
        K::FileErrorTitle => m(
            lang,
            "The access file cannot be read",
            "L'access file non è leggibile",
        ),
        K::FileErrorHint => m(
            lang,
            "Every page here re-reads the file on each request, so fixing it takes effect at \
             once — no restart, no reload.",
            "Ogni pagina qui rilegge il file a ogni richiesta, quindi correggerlo ha effetto \
             subito — senza riavvio né reload.",
        ),
        K::SignOut => m(lang, "Sign out", "Esci"),
        K::Settings => m(lang, "Preferences", "Preferenze"),
        K::AccountMenu => m(lang, "account menu", "menu dell'account"),
        // The words §13.28 §5 reserved and §13.30 §1 pins, in both languages: the row names what
        // the press costs, since the worker's deletion is the one action here no administrator
        // can undo.
        K::AccountDelete => m(
            lang,
            "Delete account and all its data",
            "Elimina l'account e tutti i suoi dati",
        ),
        K::SettingLanguage => m(lang, "Language", "Lingua"),
        K::SettingTheme => m(lang, "Theme", "Tema"),
        // Named after what decides when nobody has: the browser. "Auto" alone would leave an
        // operator guessing what it follows, and this is the one option whose answer is not
        // written next to it in the list.
        K::LangAuto => m(lang, "Auto (browser)", "Auto (browser)"),
        K::Apply => m(lang, "Apply", "Applica"),
        K::ThemeLight => m(lang, "Light", "Chiaro"),
        K::ThemeDark => m(lang, "Dark", "Scuro"),
        K::ThemeSystem => m(lang, "Auto (system)", "Auto (sistema)"),

        K::Add => m(lang, "add", "aggiungi"),
        K::Edit => m(lang, "edit", "modifica"),
        K::Remove => m(lang, "remove", "rimuovi"),
        K::Rotate => m(lang, "rotate", "rigenera"),
        K::Save => m(lang, "Save", "Salva"),
        K::Create => m(lang, "Create", "Crea"),
        K::Cancel => m(lang, "cancel", "annulla"),
        K::MoveUp => m(lang, "move up", "sposta su"),
        K::MoveDown => m(lang, "move down", "sposta giù"),
        K::KeyScopeInherit => m(
            lang,
            "everything its owner reaches",
            "tutto ciò che raggiunge il proprietario",
        ),
        K::KeyScopesHelp => m(
            lang,
            "One 'application/scope' per line, and a restriction rather than a grant: it can \
             only subtract from what the owner already reaches. Empty means all of them.",
            "Un 'applicazione/scope' per riga, ed è una restrizione, non una concessione: può \
             solo sottrarre a ciò che il proprietario già raggiunge. Vuoto vuol dire tutti.",
        ),
        K::ScopeUrlsHelp => m(
            lang,
            "One URL pattern per line. Every one of them must lie inside the application's \
             base, and first match wins, so a broad scope listed early silences the ones \
             below it.",
            "Un pattern di URL per riga. Ognuno deve stare dentro la base \
             dell\u{2019}applicazione, e vince la prima corrispondenza, quindi uno scope ampio \
             messo presto zittisce quelli sotto.",
        ),
        K::BaseHelp => m(
            lang,
            "One literal URL prefix per line, with no wildcards: this is the area the \
             application owns. No two applications may overlap, and every scope pattern must \
             lie inside one of these.",
            "Un prefisso di URL letterale per riga, senza wildcard: è l\u{2019}area che \
             l\u{2019}applicazione possiede. Due applicazioni non possono sovrapporsi, e ogni \
             pattern di scope deve stare dentro uno di questi.",
        ),
        K::LoginUrlHelp => m(
            lang,
            "The sign-in page for this whole area, overriding BB_AUTH_LOGIN_URL. Absolute \
             https. Empty uses the global one.",
            "La pagina di accesso per tutta quest\u{2019}area, che sostituisce \
             BB_AUTH_LOGIN_URL. Https assoluto. Vuoto usa quella globale.",
        ),
        K::DeniedUrlHelp => m(
            lang,
            "The page a refusal lands on for this whole area, overriding the global one. \
             Absolute https. Empty uses the global, which is itself empty for the gate\u{2019}s \
             own /auth/denied.",
            "La pagina su cui atterra un rifiuto per tutta quest\u{2019}area, che sostituisce \
             quella globale. Https assoluto. Vuoto usa quella globale, che a sua volta vuota \
             significa la /auth/denied del gate stesso.",
        ),
        K::AccessHelp => m(
            lang,
            "What this scope asks of an identity. It is required and has no default, because \
             it decides everything.",
            "Cosa chiede questo scope a un\u{2019}identità. È obbligatorio e non ha default, \
             perché decide tutto.",
        ),
        K::CredentialsHelp => m(
            lang,
            "Which classes of credential may exercise this grant. Neither ticked means both, \
             which is what an absent field says in the file.",
            "Quali classi di credenziale possono esercitare questa concessione. Nessuna delle \
             due spuntate vuol dire entrambe, che è ciò che dice un campo assente nel file.",
        ),
        K::MembersHelp => m(
            lang,
            "One per line: an email or a uuid for a person, '@name' for a group. An email is \
             resolved to the uuid the file stores.",
            "Uno per riga: un\u{2019}email o un uuid per una persona, '@nome' per un gruppo. \
             Un\u{2019}email viene risolta nell\u{2019}uuid che il file memorizza.",
        ),
        K::AnonymousWarn => m(
            lang,
            "no credential at all is asked for: these urls are open to everyone, and the 204 \
             names nobody. Note that denied does not reach here, because a vetoed client would \
             simply send nothing.",
            "non viene chiesta alcuna credenziale: questi urls sono aperti a tutti, e il 204 \
             non nomina nessuno. Nota che denied non arriva fin qui, perché un client vetato \
             basterebbe che non mandasse nulla.",
        ),
        K::AuthenticatedWarn => m(
            lang,
            "any identity Cognito vouches for reaches these urls, enrolled or not, and the \
             roster is not consulted. Self-signup is open, so that means anyone who can \
             register: the right grant for an onboarding area, the wrong one for anything else.",
            "ogni identità garantita da Cognito raggiunge questi urls, iscritta o no, e il \
             roster non viene consultato. La registrazione è aperta, quindi vuol dire chiunque \
             possa registrarsi: la concessione giusta per un\u{2019}area di onboarding, \
             sbagliata per tutto il resto.",
        ),
        K::WarnShadowed => m(
            lang,
            "unreachable: an earlier scope of this application already covers every url it \
             has",
            "irraggiungibile: uno scope precedente di questa applicazione copre già ogni url \
             che ha",
        ),
        K::WarnNoMembers => m(
            lang,
            "restricted and lists nobody: it admits no one",
            "ristretto e non elenca nessuno: non ammette nessuno",
        ),
        K::UnknownMember => m(
            lang,
            "matches no roster row",
            "non corrisponde a nessuna riga del roster",
        ),
        K::GroupMembersHelp => m(
            lang,
            "The people this name stands for, one per line, by email or uuid. A group cannot \
             reference another group.",
            "Le persone per cui sta questo nome, una per riga, per email o uuid. Un gruppo non \
             può referenziarne un altro.",
        ),
        K::GroupNoRename => m(
            lang,
            "There is deliberately no rename: a reference names a group by its exact \
             spelling. Add the new name, move the references, then remove the old one.",
            "La rinomina non esiste di proposito: un riferimento nomina il gruppo con la sua \
             esatta grafia. Aggiungi il nuovo nome, sposta i riferimenti, poi rimuovi il \
             vecchio.",
        ),
        K::NewName => m(lang, "name (rename)", "nome (rinomina)"),

        K::Filter => m(lang, "filter", "filtro"),
        K::FilterPeople => m(lang, "email, uuid or key id", "email, uuid o id chiave"),
        K::FilterMembers => m(lang, "email or uuid", "email o uuid"),
        K::FilterClear => m(lang, "clear the filter", "azzera il filtro"),
        K::PagePrev => m(lang, "previous", "precedente"),
        K::PageNext => m(lang, "next", "successiva"),
        K::PagerRows => m(lang, "rows {0}–{1} of {2}", "righe {0}–{1} di {2}"),
        K::PagerRowsFiltered => m(
            lang,
            "rows {0}–{1} of {2} (filtered from {3})",
            "righe {0}–{1} di {2} (filtrate da {3})",
        ),
        K::NoMatch => m(
            lang,
            "nothing here matches that filter.",
            "niente qui corrisponde a quel filtro.",
        ),

        K::Excluded => m(lang, "excluded", "esclusi"),
        K::ExcludedHelp => m(
            lang,
            "Kept OUT of this scope, whatever else admits them: one per line, an email or a \
             uuid for a person, '@name' for a group. Checked before the grant, so it beats a \
             group membership and it beats 'authenticated'. An email nobody here owns is kept \
             as written \u{2014} that is how a stranger is excluded.",
            "Tenuti FUORI da questo scope, qualunque altra cosa li ammetta: uno per riga, \
             un\u{2019}email o un uuid per una persona, '@nome' per un gruppo. Controllato prima \
             della concessione, quindi batte l\u{2019}appartenenza a un gruppo e batte \
             \u{2018}authenticated\u{2019}. Un\u{2019}email che qui non è di nessuno resta com\u{2019}è \
             scritta: è così che si esclude un estraneo.",
        ),
        K::ExcludedNone => m(lang, "nobody", "nessuno"),
        K::CredNoneNeeded => m(lang, "none needed", "nessuna necessaria"),

        K::ConfirmUserRm => m(
            lang,
            "The roster row goes, and every api key it owns with it. It does NOT keep them \
             off an authenticated scope: the roster is not consulted there; that is what \
             denied is for.",
            "Sparisce la riga del roster, e con essa ogni sua api key. NON li tiene fuori da \
             uno scope authenticated: lì il roster non viene consultato; per quello c'è \
             denied.",
        ),
        K::ConfirmKeyRm => m(
            lang,
            "The bearer stops working the moment the gate reloads. It cannot be restored — \
             only a new key can be minted.",
            "Il bearer smette di funzionare appena il gate ricarica. Non è recuperabile — si \
             può solo generare una chiave nuova.",
        ),
        K::ConfirmKeyRotate => m(
            lang,
            "A new bearer is minted and shown once, here. The old one stops working at the \
             next reload — which is what makes this the answer to a leak.",
            "Viene generato un nuovo bearer, mostrato una volta sola, qui. Il vecchio smette \
             di funzionare al prossimo reload — ed è per questo che è la risposta a una fuga.",
        ),
        K::ConfirmScopeRm => m(
            lang,
            "Removing this scope takes away every grant it made, and the scope after it \
             starts answering for the urls it covered.",
            "Rimuovere questo scope toglie ogni concessione che faceva, e lo scope successivo \
             comincia a rispondere per gli urls che copriva.",
        ),
        K::ConfirmEmailRm => m(
            lang,
            "This address stops signing in as this user. The identity, its groups and its \
             keys stay exactly as they are.",
            "Questo indirizzo smette di accedere come questo utente. L\u{2019}identita, i suoi \
             gruppi e le sue chiavi restano esattamente come sono.",
        ),
        K::ConfirmAppRm => m(
            lang,
            "If any of its scopes was authenticated, the identities it let in with no roster \
             entry now reach nothing.",
            "Se uno dei suoi scope era authenticated, le identità che entravano senza riga nel \
             roster ora non raggiungono nulla.",
        ),
        K::ConfirmGroupRm => m(
            lang,
            "A group is abbreviation, not a grant. Removing one is refused while any list \
             still names it.",
            "Un gruppo è un'abbreviazione, non una concessione. Rimuoverlo viene rifiutato \
             finché una lista lo nomina.",
        ),
        K::ConfirmDenyRm => m(
            lang,
            "The veto is lifted. Whatever the roster and the scopes grant them applies again.",
            "Il veto viene tolto. Torna a valere quanto gli concedono il roster e gli scope.",
        ),

        K::BearerHeading => m(
            lang,
            "The bearer — copy it now",
            "Il bearer — copialo adesso",
        ),
        K::BearerOnce => m(
            lang,
            "Shown once, here, and stored nowhere: the file keeps only its sha256, and that \
             lookup is the whole verification. It cannot be recovered — only replaced by a \
             rotation.",
            "Mostrato una volta sola, qui, e non memorizzato da nessuna parte: il file tiene \
             solo il suo sha256, e quel lookup è tutta la verifica. Non è recuperabile — si \
             può solo sostituire con una rotazione.",
        ),
        K::BearerHintLead => m(
            lang,
            "Click the key to select it all, then copy. Send it as a bearer token: the word",
            "Fai clic sulla chiave per selezionarla tutta, poi copiala. Mandala come token \
             bearer: la parola",
        ),
        K::BearerHintTail => m(lang, ", a space, then the key.", ", uno spazio, poi la chiave."),
        K::CopyKey => m(lang, "Copy the key", "Copia la chiave"),
        K::CopyDone => m(lang, "Copied", "Copiata"),
        K::CopyFailed => m(
            lang,
            "Copy refused: the key is selected, copy it with the keyboard.",
            "Copia negata: la chiave è selezionata, copiala con la tastiera.",
        ),

        K::ExcludedNotAnon => m(
            lang,
            "an anonymous scope grants with no credential at all, so an excluded client would \
             simply send none. Make it authenticated, or narrow the urls",
            "uno scope anonymous concede senza alcuna credenziale, quindi un client escluso \
             semplicemente non ne manderebbe nessuna. Rendilo authenticated, o restringi le url",
        ),
        K::EmailRequired => m(lang, "an email is required", "serve un'email"),
        K::NameRequired => m(lang, "a name is required", "serve un nome"),
        K::KeyIdRequired => m(
            lang,
            "a key needs an id — it is what names it in a log and in a rotation",
            "una chiave ha bisogno di un id — è ciò che la nomina in un log e in una rotazione",
        ),
        K::BadKeyWindow => m(
            lang,
            "released + duration is not a valid window: a date is YYYY-MM-DD, a duration is \
             <n>d, <n>h or never. The gate would skip this key.",
            "released + duration non sono una finestra valida: una data è YYYY-MM-DD, una \
             durata è <n>d, <n>h o never. Il gate salterebbe questa chiave.",
        ),
        K::AlreadyDenied => m(
            lang,
            "that email is already on denied",
            "quell'email è già in denied",
        ),
        K::NoSuchKey => m(lang, "no such api key", "api key inesistente"),
        K::NoSuchApp => m(lang, "no such application", "applicazione inesistente"),
        K::NoSuchScope => m(lang, "no such scope", "scope inesistente"),
        K::NoSuchGroup => m(lang, "no such user group", "gruppo di utenti inesistente"),
        K::NoSuchDenied => m(
            lang,
            "that email is not on denied",
            "quell'email non è in denied",
        ),

        K::ConflictTitle => m(lang, "The file changed", "Il file è cambiato"),
        K::ConflictBody => m(
            lang,
            "The access file was written by someone else after this form was loaded — a \
             bb-auth-adm over SSH, or another tab. Nothing was written here: reload the page \
             and make the change again, on what the file says now.",
            "L'access file è stato scritto da qualcun altro dopo il caricamento di questa \
             form — un bb-auth-adm via SSH, o un'altra scheda. Qui non è stato scritto \
             nulla: ricarica la pagina e rifai la modifica su ciò che il file dice adesso.",
        ),
        K::ConflictRecover => m(
            lang,
            "What you typed is not lost: the browser's Back button returns to the form as \
             you filled it in — copy the values from there onto the freshly reloaded form.",
            "Ciò che avevi digitato non è perso: il pulsante Indietro del browser riporta \
             alla form così come l'avevi compilata — copia da lì i valori sulla form appena \
             ricaricata.",
        ),
        K::ConflictBack => m(lang, "reload the page", "ricarica la pagina"),
        K::MintConflictTitle => m(
            lang,
            "This key was already created",
            "Questa chiave è già stata creata",
        ),
        K::MintConflictBody => m(
            lang,
            "The file already carries a key with this id for this user — most likely this \
             page is a reload of the one that showed the bearer, re-submitting the mint \
             form. Nothing was written now: the key exists exactly once.",
            "Il file contiene già una chiave con questo id per questo utente — con ogni \
             probabilità questa pagina è il ricaricamento di quella che mostrava il bearer, \
             e ha reinviato la form di creazione. Adesso non è stato scritto nulla: la \
             chiave esiste una volta sola.",
        ),
        K::MintConflictLost => m(
            lang,
            "The bearer was shown once, when the key was created, and cannot be recovered — \
             the file keeps only its hash. If it was not copied then, rotate the key: same \
             row, same scope, a new secret.",
            "Il bearer è stato mostrato una sola volta, alla creazione della chiave, e non \
             può essere recuperato — il file ne conserva solo l'hash. Se allora non è stato \
             copiato, rigenera la chiave: stessa riga, stesso scope, un nuovo segreto.",
        ),
        K::MintConflictRotate => m(lang, "rotate this key", "rigenera questa chiave"),
        K::RotateConflictTitle => m(
            lang,
            "This key was already rotated",
            "Questa chiave è già stata rigenerata",
        ),
        K::RotateConflictBody => m(
            lang,
            "Most likely this page is a reload of the one that showed the new bearer, \
             re-submitting the rotation. Nothing was written now, which matters here: \
             rotating again would invalidate the bearer that page showed, and leave you on \
             this same page.",
            "Con ogni probabilità questa pagina è il ricaricamento di quella che mostrava \
             il nuovo bearer, e ha reinviato la rigenerazione. Adesso non è stato scritto \
             nulla, il che qui conta: rigenerare di nuovo invaliderebbe il bearer che quella \
             pagina mostrava, e ti riporterebbe su questa stessa pagina.",
        ),
        K::CsrfTitle => m(lang, "Request refused", "Richiesta rifiutata"),
        K::CsrfBody => m(
            lang,
            "this POST did not come from a page of this site. Only a same-origin form \
             submission is accepted.",
            "questo POST non arriva da una pagina di questo sito. Si accetta solo l'invio di \
             una form dalla stessa origine.",
        ),
        K::NotAllowedTitle => m(lang, "Not allowed here", "Non ammesso qui"),
        K::NotAllowedBody => m(
            lang,
            "this address does not answer that method.",
            "questo indirizzo non risponde a quel metodo.",
        ),

        K::MsgUserAdded => m(lang, "user added", "utente aggiunto"),
        K::MsgUserSaved => m(lang, "user saved", "utente salvato"),
        K::MsgUserRemoved => m(lang, "user removed", "utente rimosso"),
        K::MsgKeySaved => m(lang, "api key saved", "api key salvata"),
        K::MsgKeyRemoved => m(lang, "api key removed", "api key rimossa"),
        K::MsgAppAdded => m(lang, "application added", "applicazione aggiunta"),
        K::MsgAppSaved => m(lang, "application saved", "applicazione salvata"),
        K::MsgAppRemoved => m(lang, "application removed", "applicazione rimossa"),
        K::MsgScopeAdded => m(lang, "scope added", "scope aggiunto"),
        K::MsgScopeSaved => m(lang, "scope saved", "scope salvato"),
        K::MsgScopeRemoved => m(lang, "scope removed", "scope rimosso"),
        K::MsgScopeMoved => m(lang, "scope moved", "scope spostato"),
        K::MsgGroupAdded => m(lang, "user group added", "gruppo di utenti aggiunto"),
        K::MsgGroupSaved => m(lang, "user group saved", "gruppo di utenti salvato"),
        K::MsgGroupRemoved => m(lang, "user group removed", "gruppo di utenti rimosso"),
        K::MsgDeniedAdded => m(lang, "email denied", "email negata"),
        K::MsgDeniedRemoved => m(lang, "veto lifted", "veto tolto"),

        // --- the self-service page ---
        //
        // The headings are the prose, and the only prose: the names in each section are the
        // access file's vocabulary, which is never translated.
        K::AccountTitle => m(lang, "Your account", "Il tuo account"),
        K::AccountIdLabel => m(lang, "Account id", "Id dell'account"),
        // The refusal a mint gets from a caller with no row. It says what is missing rather
        // than blaming the request, because the person reading it is the one who has to ask
        // for the row.
        K::AccountNoRowTitle => m(
            lang,
            "There is no account to mint into",
            "Non c'è un account in cui creare la chiave",
        ),
        K::AccountNoRowBody => m(
            lang,
            "bb-auth has no roster row for this identity, so there is no account a key of \
             yours could belong to.",
            "bb-auth non ha una riga nella lista per questa identità, quindi non c'è un account \
             a cui una tua chiave possa appartenere.",
        ),
        K::AccountReach => m(lang, "Where you reach", "Dove puoi arrivare"),
        K::AccountReachSub => m(
            lang,
            "The applications your sign-in opens, and the areas inside each.",
            "Le applicazioni a cui il tuo accesso apre la porta, e le aree dentro ciascuna.",
        ),
        K::AccountReachNone => m(
            lang,
            "Your sign-in opens no application yet.",
            "Il tuo accesso non apre ancora nessuna applicazione.",
        ),
        // The page's own word for the file's `user_groups` section, not the console's `K::Groups`
        // ("User groups"), which names the file section an administrator edits.
        K::AccountGroups => m(lang, "Groups", "Gruppi"),
        K::AccountGroupsSub => m(
            lang,
            "Groups an administrator has put you in.",
            "I gruppi in cui ti ha messo un amministratore.",
        ),
        K::AccountGroupsNone => m(lang, "You are in no group.", "Non sei in nessun gruppo."),
        K::AccountKeys => m(lang, "API keys", "Chiavi API"),
        K::AccountKeysSub => m(
            lang,
            "A key lets a script or a tool sign in as you. It reaches at most what you reach.",
            "Una chiave permette a uno script o a uno strumento di accedere come te. Arriva al \
             massimo dove arrivi tu.",
        ),
        K::AccountProfile => m(lang, "Profile", "Profilo"),
        K::AccountProfileSub => m(
            lang,
            "What your sign-in tells your applications about you.",
            "Cosa il tuo accesso dice di te alle tue applicazioni.",
        ),
        K::AccountProfileNone => m(
            lang,
            "This deployment shares no profile details.",
            "Questa installazione non condivide dettagli del profilo.",
        ),
        // A claim the deployment configured and the proxy did not forward. Lowercase, because it
        // reads as the tail of the row's sentence, after the claim's name, not as a heading.
        K::AccountNotProvided => m(lang, "not provided", "non fornito"),
        // The profile edit (§13.23 §5). The wording is the designer's table, verbatim, and the
        // sentences around a value are split into separate keys (`CodeSent` / `CodeLasts`,
        // `Was` / `Removed`) because the table has no placeholders and a sentence built by
        // gluing a value into the middle of a string is a sentence that reads wrong in one of
        // the two languages.
        K::AccountProfileEdit => m(lang, "Edit profile", "Modifica il profilo"),
        K::AccountProfileEditSub => m(
            lang,
            "Change what you need, then confirm with a code we email you.",
            "Cambia ciò che ti serve, poi conferma con un codice che ti mandiamo per email.",
        ),
        K::AccountProfileClearDeletes => m(
            lang,
            "Empty it to remove it.",
            "Svuotalo per eliminarlo.",
        ),
        K::AccountProfileDateHint => m(lang, "YYYY-MM-DD", "AAAA-MM-GG"),
        // The one sentence the profile panel says to a person whose session is not a native
        // Cognito sign-in (§13.25): the profile of a federated account belongs to the provider,
        // and a session minted before the gate named the Cognito user has to sign in again to
        // reach the edit. It says what to do, not only what is wrong.
        K::AccountProfileNotNative => m(
            lang,
            "If you sign in with a social account such as Google, your profile comes from that \
             provider and cannot be changed here. If you sign in with your email address, sign \
             out and sign in again to edit it.",
            "Se accedi con un account social come Google, il tuo profilo viene da quel fornitore \
             e non si può cambiare qui. Se accedi con il tuo indirizzo email, esci e accedi di \
             nuovo per modificarlo.",
        ),
        K::AccountProfileEmailFixed => m(
            lang,
            "Your email address is how you sign in, so only an administrator can change it.",
            "Il tuo indirizzo email è il modo in cui accedi, quindi solo un amministratore può cambiarlo.",
        ),
        K::AccountProfileSendCode => m(lang, "Send code", "Invia il codice"),
        K::AccountProfileNothingChanged => m(
            lang,
            "Nothing to save: every field is as it was, so no code was sent.",
            "Niente da salvare: ogni campo è com'era, quindi non è stato inviato alcun codice.",
        ),
        K::AccountProfileValueBad => m(
            lang,
            "too long, or holds characters that cannot be saved.",
            "troppo lungo, o contiene caratteri che non si possono salvare.",
        ),
        K::AccountProfileCannotEdit => m(
            lang,
            "cannot be changed here.",
            "non si può cambiare qui.",
        ),
        K::AccountProfileCodeTitle => m(lang, "Enter the code", "Inserisci il codice"),
        K::AccountProfileCodeSent => m(
            lang,
            "We emailed a code to",
            "Abbiamo inviato un codice a",
        ),
        // The same sentence with no address in it, for the case the provider does not name one
        // (§13.25): the code went to the address the account signs in with, and the page may say
        // that much without inventing an address it was not given.
        K::AccountProfileCodeSentNoDest => m(
            lang,
            "We emailed a code to the address you sign in with.",
            "Abbiamo inviato un codice all'indirizzo con cui accedi.",
        ),
        K::AccountProfileCodeLasts => m(
            lang,
            "It works for 3 minutes.",
            "Vale per 3 minuti.",
        ),
        K::AccountProfileChanges => m(lang, "What will change", "Cosa cambierà"),
        K::AccountProfileWas => m(lang, "was", "prima:"),
        K::AccountProfileRemoved => m(lang, "removed", "eliminato"),
        K::AccountProfileCodeLabel => m(lang, "Code", "Codice"),
        K::AccountProfileSave => m(lang, "Save profile", "Salva il profilo"),
        K::AccountProfileNoCode => m(
            lang,
            "No email after a minute? Look in your spam folder, or send a new code.",
            "Nessuna email dopo un minuto? Guarda nello spam, o invia un nuovo codice.",
        ),
        K::AccountProfileSendNew => m(lang, "Send a new code", "Invia un nuovo codice"),
        K::AccountProfileNotSavedTitle => m(
            lang,
            "Your profile was not changed",
            "Il tuo profilo non è stato modificato",
        ),
        K::AccountProfileNoAnswer => m(
            lang,
            "The sign-in service did not answer within 5 seconds. Try again in a minute.",
            "Il servizio di accesso non ha risposto entro 5 secondi. Riprova tra un minuto.",
        ),
        // The account the session named is gone from the pool (`UserNotFoundException`,
        // `UserNotConfirmedException`), so there is nobody to send a code to. It says so in the
        // same breath as what to do about it, because the person's own sign-in is the thing that
        // has to be redone.
        K::AccountProfileNoUser => m(
            lang,
            "The sign-in service no longer has the account you signed in with, so no code was \
             sent. Sign out and sign in again.",
            "Il servizio di accesso non ha più l'account con cui hai effettuato l'accesso, \
             quindi non è stato inviato alcun codice. Esci e accedi di nuovo.",
        ),
        K::AccountProfileTooMany => m(
            lang,
            "Too many attempts. Wait a few minutes, then try again.",
            "Troppi tentativi. Aspetta qualche minuto, poi riprova.",
        ),
        K::AccountProfileRefused => m(
            lang,
            "The sign-in service refused the change.",
            "Il servizio di accesso ha rifiutato la modifica.",
        ),
        K::AccountProfileWrongCode => m(
            lang,
            "That code is not right. Use the code in the latest email, and type it again.",
            "Il codice non è corretto. Usa il codice dell'ultima email e scrivilo di nuovo.",
        ),
        K::AccountProfileExpired => m(
            lang,
            "The code has expired. Send a new one, and type it as soon as it arrives.",
            "Il codice è scaduto. Inviane uno nuovo e scrivilo appena arriva.",
        ),
        K::AccountProfileNotYours => m(
            lang,
            "The sign-in service answered for a different account, so nothing was changed.",
            "Il servizio di accesso ha risposto per un altro account, quindi non è cambiato nulla.",
        ),
        K::AccountProfileBadValue => m(
            lang,
            "The sign-in service did not accept one of the values. Check the date (YYYY-MM-DD) \
             and the web addresses, then try again.",
            "Il servizio di accesso non ha accettato uno dei valori. Controlla la data \
             (AAAA-MM-GG) e gli indirizzi web, poi riprova.",
        ),
        K::AccountProfileSavedTitle => m(lang, "Profile saved", "Profilo salvato"),
        K::AccountProfileSavedLead => m(lang, "Changed:", "Modificato:"),
        K::AccountProfileSavedBody => m(
            lang,
            "Your applications, and this page, show it from your next sign-in.",
            "Le tue applicazioni, e questa pagina, lo mostrano dal prossimo accesso.",
        ),
        K::AccountProfileUnsureTitle => m(
            lang,
            "Your profile may not have been saved",
            "Il tuo profilo potrebbe non essere stato salvato",
        ),
        K::AccountProfileNoAnswerUnsure => m(
            lang,
            "The sign-in service accepted the code, then did not answer within 5 seconds, so the \
             change may or may not have been made. Your next sign-in will show which.",
            "Il servizio di accesso ha accettato il codice, poi non ha risposto entro 5 secondi: \
             la modifica potrebbe essere stata fatta oppure no. Il prossimo accesso lo mostrerà.",
        ),
        K::AttrName => m(lang, "Full name", "Nome completo"),
        K::AttrGivenName => m(lang, "Given name", "Nome"),
        K::AttrFamilyName => m(lang, "Family name", "Cognome"),
        K::AttrMiddleName => m(lang, "Middle name", "Secondo nome"),
        K::AttrNickname => m(lang, "Nickname", "Soprannome"),
        K::AttrProfile => m(lang, "Profile page", "Pagina del profilo"),
        K::AttrPicture => m(
            lang,
            "Picture (web address)",
            "Immagine (indirizzo web)",
        ),
        K::AttrWebsite => m(lang, "Website", "Sito web"),
        K::AttrGender => m(lang, "Gender", "Genere"),
        K::AttrBirthdate => m(lang, "Date of birth", "Data di nascita"),
        K::AttrZoneinfo => m(lang, "Time zone", "Fuso orario"),
        K::AttrLocale => m(lang, "Language and region", "Lingua e regione"),
        // The keys' empty state names keys, in the feminine (*chiavi*): Italian agrees an
        // adjective with the noun it stands for, and the section's heading is the noun a reader
        // sees beside the sentence, so a borrowed pronoun reads as a slip in the page's own
        // language.
        K::AccountKeysNone => m(
            lang,
            "No API keys yet.",
            "Non ci sono ancora chiavi API.",
        ),
        // The mint form. `id` and `duration` are the file's own field names and stay as
        // written in it, exactly as the console's key form leaves them.
        K::AccountKeyAdd => m(lang, "Add a key", "Aggiungi una chiave"),
        K::AccountKeyCreate => m(lang, "Create key", "Crea la chiave"),
        K::AccountKeyIdHint => m(
            lang,
            "lowercase letters, digits and dashes, up to 32",
            "lettere minuscole, cifre e trattini, fino a 32",
        ),
        // The mint form's two field labels. The **field names** stay `id` and `duration`,
        // because the handler reads those and the file stores those; the label is the page's
        // word for the thing, and a label is displayed text. The Italian noun is the one this
        // page's own refusals use (`AccountKeyIdBad` says "Il nome di una chiave", `AccountKeyDup`
        // "quel nome"), so the form and the refusal name the field alike, and the file's word
        // `id` never appears on this page.
        // The two forms every key of the caller's carries. The verbs are this page's, not the
        // console's (`K::Rotate` / `K::Remove` are an operator's lowercase command words): a
        // person with no administrator in the room is clicking a button that says what it does.
        K::AccountKeyRotate => m(lang, "Rotate key", "Rigenera la chiave"),
        K::AccountKeyRemove => m(lang, "Revoke key", "Revoca la chiave"),
        // The refusals this form answers with. Each names what to write instead, because a
        // person with no administrator at hand has to fix it themselves, and each says **one**
        // fact: the `AccountKeyBound` these replaced named the id and the window in the same
        // sentence, so a person who typed `My Laptop` read about durations (WCAG 3.3.1 and
        // 3.3.3: identify the error in text, name the fix).
        K::AccountKeyIdBad => m(
            lang,
            "A key name is lowercase letters, digits and dashes, up to 32 characters, such as \
             laptop.",
            "Il nome di una chiave è fatto di lettere minuscole, cifre e trattini, fino a 32 \
             caratteri, per esempio laptop.",
        ),
        K::AccountKeyTooShort => m(
            lang,
            "A key must last at least a day; choose a longer duration.",
            "Una chiave deve durare almeno un giorno; scegli una durata più lunga.",
        ),
        K::AccountKeyFull => m(
            lang,
            "This account has ten keys, which is the most this page mints.",
            "Questo account ha dieci chiavi, il massimo che questa pagina crea.",
        ),
        K::AccountKeyDup => m(
            lang,
            "This account already has a key with that name.",
            "Questo account ha già una chiave con quel nome.",
        ),
        K::AccountKeyUnknownScope => m(
            lang,
            "A scope you picked is not one a key of yours can reach.",
            "Uno degli ambiti scelti non è uno che una tua chiave può raggiungere.",
        ),
        // The keys table and its `+ New key` row (§13.16). The two column words are the
        // table's headings **and** the mint form's field labels, so a field and the column
        // that shows the same value answer that value's name from one entry, and an Italian
        // page cannot carry a label in English.
        K::AccountKeyNew => m(lang, "+ New key", "+ Nuova chiave"),
        K::AccountKeyFullRow => m(
            lang,
            "An account holds at most 10 keys. Revoke one to add another.",
            "Un account ha al massimo 10 chiavi. Revocane una per aggiungerne un'altra.",
        ),
        // The last clause is the reason it is spelled out: a rotate stamps a new `released`,
        // so the window starts again, which is not what "rotate the secret" sounds like.
        K::AccountKeyRotateWarn => m(
            lang,
            "A new secret replaces this one. Anything still using the old one stops getting \
             in within seconds. The name and the scopes stay; the expiry starts again from \
             today.",
            "Un nuovo segreto sostituisce questo. Ciò che usa il vecchio smette di entrare in \
             pochi secondi. Il nome e gli ambiti restano; la scadenza riparte da oggi.",
        ),
        K::AccountKeyRemoveWarn => m(
            lang,
            "The key stops working within seconds. This cannot be undone: only a new key can \
             replace it.",
            "La chiave smette di funzionare in pochi secondi. Non si può annullare: solo una \
             nuova chiave può sostituirla.",
        ),
        K::KeyColName => m(lang, "Name", "Nome"),
        K::KeyColExpires => m(lang, "Expires", "Scade"),
        K::KeyScopesAll => m(lang, "all scopes", "tutti gli ambiti"),
        K::KeyScopesOnly => m(lang, "only these", "solo questi"),
        K::KeyScopeGone => m(lang, "no longer reached", "non più raggiungibile"),
        // The twin of the console's refusal for the same contradiction: the ticks say one
        // thing and the radio says another, and the person has to pick which one they meant.
        K::KeyScopesWithoutOnly => m(
            lang,
            "You ticked scopes; choose 'only these', or untick them.",
            "Hai spuntato degli ambiti; scegli 'solo questi', o togli la spunta.",
        ),
        // The answer to a `restrict` that is neither of the two the form sends, which only a
        // hand-written `POST` achieves. No field is marked: the request chose nothing, and the
        // honest fix names the two choices it could have chosen.
        K::KeyScopesChoose => m(
            lang,
            "Choose 'all scopes' or 'only these'.",
            "Scegli 'tutti gli ambiti' o 'solo questi'.",
        ),
        // The five duration choices (§13.15). The words are the person's; the values the
        // control posts are the file's (`365d`, `182d`, `91d`, `custom`, `never`), so the
        // stored string is the spelling `bb-auth-adm show` prints.
        K::DurOneYear => m(lang, "in 1 year", "tra 1 anno"),
        K::DurSixMonths => m(lang, "in 6 months", "tra 6 mesi"),
        K::DurThreeMonths => m(lang, "in 3 months", "tra 3 mesi"),
        K::DurCustom => m(lang, "after a number of days", "dopo un numero di giorni"),
        K::DurNever => m(lang, "never", "mai"),
        // The box's own name. It echoes the option the person picked ("after a number of
        // days") and contains the placeholder's word, where "Custom duration" named nothing
        // on screen (WCAG 2.5.3, label in name).
        K::DurDaysLabel => m(lang, "Number of days", "Numero di giorni"),
        K::DurDaysHint => m(lang, "days", "giorni"),
        // The three refusals `duration_from_form` answers with, each naming its own fix,
        // because the person reading them has no administrator in the room. They sit beside
        // `KeyDurationRequired`, already a sentence, in the same box.
        K::KeyDurationRequired => m(
            lang,
            "Choose how long the key lasts.",
            "Scegli per quanto tempo dura la chiave.",
        ),
        K::KeyDaysWithoutCustom => m(
            lang,
            "You typed a number of days; choose 'after a number of days', or clear it.",
            "Hai scritto un numero di giorni; scegli 'dopo un numero di giorni', o cancellalo.",
        ),
        K::KeyDaysInvalid => m(
            lang,
            "Write a whole number of days, at least 1.",
            "Scrivi un numero intero di giorni, almeno 1.",
        ),
        // One sentence for "no such key" and "that key belongs to somebody else", because a
        // page that answered the two differently is an enumeration oracle for anybody with an
        // account: it would say which ids exist on the estate.
        K::AccountKeyNotYours => m(
            lang,
            "that key is not one of yours, so this page cannot rotate it or revoke it.",
            "quella chiave non è una delle tue, quindi questa pagina non può rigenerarla né \
             revocarla.",
        ),
        K::AccountVetoTitle => m(lang, "You are refused", "Sei escluso"),
        K::AccountVetoBody => m(
            lang,
            "this deployment has a veto on your identity, so there is no account to show.",
            "questa installazione ha un veto sulla tua identità, quindi non c'è un account da \
             mostrare.",
        ),
        K::AccountAmbiguousTitle => m(
            lang,
            "The identity header names two accounts",
            "L'header di identità nomina due account",
        ),
        K::AccountAmbiguousBody => m(
            lang,
            "the identity header carries addresses that belong to different roster rows, and \
             there is no page about both of them.",
            "l'header di identità porta indirizzi di righe diverse della lista, e non c'è una \
             pagina che parli di entrambe.",
        ),
        K::AccountNoEmailTitle => m(
            lang,
            "No email identity is forwarded",
            "Nessuna identità email è inoltrata",
        ),
        // Names the setting, because the operator reading this is the only person who can fix
        // it, and a page that only said "no identity" would send them to the wrong file.
        K::AccountNoEmailBody => m(
            lang,
            "gate.identity_attrs names no email, so the proxy forwards no identity for this \
             page to act on.",
            "gate.identity_attrs non nomina l'email, quindi il proxy non inoltra nessuna \
             identità su cui questa pagina può agire.",
        ),
        // The delete confirmation page (§13.30 §2 §5). The English is the designer's table
        // verbatim, and the Italian keeps one fixed name per thing: "account di accesso" for a
        // sign-in account, "servizio di eliminazione" for the deletion service.
        K::AccountDeleteTitle => m(
            lang,
            "Delete your account",
            "Elimina il tuo account",
        ),
        K::AccountDeleteLead => m(
            lang,
            "This cannot be undone. To confirm, type your email address below and press Delete \
             my account.",
            "Non si può annullare. Per confermare, scrivi qui sotto il tuo indirizzo email e \
             premi Elimina il mio account.",
        ),
        K::AccountDeleteGoes => m(lang, "What is deleted", "Cosa viene eliminato"),
        K::AccountDeleteRecord => m(
            lang,
            "Your bb-auth record, and every access an administrator gave you by name.",
            "I tuoi dati in bb-auth, e ogni accesso che un amministratore ti ha dato per nome.",
        ),
        K::AccountDeleteKeysLead => m(
            lang,
            "Your API keys, which stop working within seconds:",
            "Le tue chiavi API, che smettono di funzionare in pochi secondi:",
        ),
        K::AccountDeleteGroupsLead => m(
            lang,
            "Your place in these groups:",
            "Il tuo posto in questi gruppi:",
        ),
        K::AccountDeleteSignInOne => m(
            lang,
            "Every sign-in account with this email address, whether you sign in with an emailed \
             code or with a provider such as Google:",
            "Ogni account di accesso con questo indirizzo email, sia che tu acceda con un codice \
             via email sia con un fornitore come Google:",
        ),
        K::AccountDeleteSignInMany => m(
            lang,
            "Every sign-in account with any of these email addresses, whether you sign in with \
             an emailed code or with a provider such as Google:",
            "Ogni account di accesso con uno di questi indirizzi email, sia che tu acceda con un \
             codice via email sia con un fornitore come Google:",
        ),
        K::AccountDeleteLater => m(
            lang,
            "The sign-in accounts are not deleted at once: they are queued for a separate \
             deletion service.",
            "Gli account di accesso non vengono eliminati subito: vengono messi in coda per un \
             servizio di eliminazione separato.",
        ),
        K::AccountDeleteAuditKept => m(
            lang,
            "The record of your sign-ins and refusals is kept for",
            "Il registro dei tuoi accessi e dei rifiuti è conservato per",
        ),
        K::AccountDeleteAuditTail => m(lang, ", then dropped.", ", poi viene eliminato."),
        K::AccountDeleteAuditSize => m(
            lang,
            "The record of your sign-ins and refusals is kept until newer entries replace it; \
             this deployment keeps at most",
            "Il registro dei tuoi accessi e dei rifiuti resta finché voci più recenti non lo \
             sostituiscono; questa installazione ne conserva al massimo",
        ),
        K::AccountDeleteTypeLabel => m(
            lang,
            "Type your email address to confirm",
            "Scrivi il tuo indirizzo email per confermare",
        ),
        K::AccountDeleteTypeHintMany => m(
            lang,
            "Any one of the addresses above.",
            "Uno qualsiasi degli indirizzi qui sopra.",
        ),
        K::AccountDeleteConfirm => m(
            lang,
            "Delete my account",
            "Elimina il mio account",
        ),
        // The words of every outcome a deletion request answers with, verbatim from §13.30 §5.
        // "Queued" and never "deleted": the page cannot read the worker's outcome (§13.29 W6).
        K::AccountDeleteQueuedTitle => m(
            lang,
            "Your account is being deleted",
            "Il tuo account è in fase di eliminazione",
        ),
        K::AccountDeleteNowGone => m(
            lang,
            "Your API keys and every access an administrator gave you by name are gone.",
            "Le tue chiavi API e ogni accesso che un amministratore ti ha dato per nome non ci \
             sono più.",
        ),
        K::AccountDeleteQueued => m(
            lang,
            "Your sign-in accounts are queued for deletion. This page cannot tell when that \
             happens; if you can still sign in later, tell an administrator.",
            "I tuoi account di accesso sono in coda per l'eliminazione. Questa pagina non può \
             dire quando avverrà; se più avanti riesci ancora ad accedere, avvisa un \
             amministratore.",
        ),
        K::AccountDeletedClose => m(
            lang,
            "This browser stays signed in until the session ends.",
            "Questo browser resta connesso finché la sessione non termina.",
        ),
        K::AccountDeletePartialTitle => m(
            lang,
            "Your account is only partly deleted",
            "Il tuo account è stato eliminato solo in parte",
        ),
        K::AccountDeleteNotQueued => m(
            lang,
            "Your sign-in accounts could not be queued for deletion, so they still exist. Try \
             again later; if it fails again, tell an administrator.",
            "Non è stato possibile mettere in coda l'eliminazione dei tuoi account di accesso, \
             che quindi esistono ancora. Riprova più tardi; se non funziona di nuovo, avvisa un \
             amministratore.",
        ),
        K::AccountDeleteUnsureTitle => m(
            lang,
            "Your account may not be fully deleted",
            "Il tuo account potrebbe non essere stato eliminato del tutto",
        ),
        K::AccountDeleteMaybeQueued => m(
            lang,
            "The deletion service did not answer, so your sign-in accounts may or may not be \
             queued for deletion. Trying again is safe, even if they were.",
            "Il servizio di eliminazione non ha risposto, quindi i tuoi account di accesso \
             potrebbero essere in coda per l'eliminazione oppure no. Riprovare non crea problemi, \
             anche se lo erano già.",
        ),
        K::AccountDeleteSome => m(
            lang,
            "The sign-in accounts of some of your addresses are queued for deletion; the others \
             may not be.",
            "Gli account di accesso di alcuni dei tuoi indirizzi sono in coda per l'eliminazione; \
             gli altri potrebbero non esserlo.",
        ),
        K::AccountDeleteUnconfirmedLead => m(
            lang,
            "Addresses not confirmed as queued:",
            "Indirizzi di cui non è confermata la messa in coda:",
        ),
        K::AccountDeleteRetryOneAddress => m(
            lang,
            "Trying again covers only the address you signed in with; for the others, tell an \
             administrator.",
            "Riprovare riguarda solo l'indirizzo con cui hai effettuato l'accesso; per gli altri, \
             avvisa un amministratore.",
        ),
        K::AccountDeleteNotDoneTitle => m(
            lang,
            "Your account was not deleted",
            "Il tuo account non è stato eliminato",
        ),
        K::AccountDeleteProtected => m(
            lang,
            "This account cannot be deleted from this page, and nothing was deleted. If you want \
             it deleted, ask an administrator.",
            "Questo account non può essere eliminato da questa pagina, e non è stato eliminato \
             nulla. Se vuoi eliminarlo, chiedi a un amministratore.",
        ),
        K::AccountDeleteNoCheck => m(
            lang,
            "The deletion service did not answer as expected, so nothing was deleted and you can \
             still sign in. Try again in a minute; if it fails again, tell an administrator.",
            "Il servizio di eliminazione non ha risposto come previsto, quindi non è stato \
             eliminato nulla e puoi ancora accedere. Riprova tra un minuto; se non funziona di \
             nuovo, avvisa un amministratore.",
        ),
        K::AccountDeleteRetry => m(lang, "Try again", "Riprova"),
        K::AccountDeleteStartAgain => m(lang, "Start again", "Ricomincia"),
        K::AccountDeleteWriteFailed => m(
            lang,
            "bb-auth could not save the change, so nothing was deleted and you can still sign \
             in. Try again in a minute; if it fails again, tell an administrator.",
            "bb-auth non è riuscito a salvare la modifica, quindi non è stato eliminato nulla e \
             puoi ancora accedere. Riprova tra un minuto; se non funziona di nuovo, avvisa un \
             amministratore.",
        ),
        K::AccountDeleteChangedTitle => m(
            lang,
            "Your account changed",
            "Il tuo account è cambiato",
        ),
        K::AccountDeleteChanged => m(
            lang,
            "Your account changed after you opened this page, so nothing was deleted. Start again \
             to see what would be deleted now.",
            "Il tuo account è cambiato dopo che hai aperto questa pagina, quindi non è stato \
             eliminato nulla. Ricomincia per vedere cosa verrebbe eliminato adesso.",
        ),
        K::AccountDeleteTypedWrong => m(
            lang,
            "The email address typed is not one of this account's, so nothing was deleted. Type \
             it as it is shown above.",
            "L'indirizzo email scritto non è uno di quelli di questo account, quindi non è stato \
             eliminato nulla. Scrivilo come appare qui sopra.",
        ),
        K::AccountDeleteTooMany => m(
            lang,
            "This account has more email addresses than this page can delete at once, so it \
             cannot be deleted here, and nothing was deleted. If you want it deleted, ask an \
             administrator.",
            "Questo account ha più indirizzi email di quanti questa pagina ne possa eliminare in \
             una volta, quindi non può essere eliminato qui, e non è stato eliminato nulla. Se \
             vuoi eliminarlo, chiedi a un amministratore.",
        ),
    }
}

/// What a successful mutation says on the page it redirects to.
///
/// A closed set, and that is the point: the `303` puts `?msg=<key>` in the URL, so what
/// comes back is request data. Only these keys render, through [`t`]; anything else is
/// dropped silently. No free text ever travels through the query string, which is what
/// keeps the banner from being a place to inject prose into an admin's page.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Msg {
    UserAdded,
    UserSaved,
    UserRemoved,
    KeySaved,
    KeyRemoved,
    AppAdded,
    AppSaved,
    AppRemoved,
    ScopeAdded,
    ScopeSaved,
    ScopeRemoved,
    ScopeMoved,
    GroupAdded,
    GroupSaved,
    GroupRemoved,
    DeniedAdded,
    DeniedRemoved,
    SettingsSaved,
}

impl Msg {
    /// The spelling in the query string — printable ASCII, so it goes into a `Location:`
    /// with no encoding.
    pub(crate) fn key(self) -> &'static str {
        match self {
            Msg::UserAdded => "user-added",
            Msg::UserSaved => "user-saved",
            Msg::UserRemoved => "user-removed",
            Msg::KeySaved => "key-saved",
            Msg::KeyRemoved => "key-removed",
            Msg::AppAdded => "app-added",
            Msg::AppSaved => "app-saved",
            Msg::AppRemoved => "app-removed",
            Msg::ScopeAdded => "scope-added",
            Msg::ScopeSaved => "scope-saved",
            Msg::ScopeRemoved => "scope-removed",
            Msg::ScopeMoved => "scope-moved",
            Msg::GroupAdded => "group-added",
            Msg::GroupSaved => "group-saved",
            Msg::GroupRemoved => "group-removed",
            Msg::DeniedAdded => "denied-added",
            Msg::DeniedRemoved => "denied-removed",
            Msg::SettingsSaved => "settings-saved",
        }
    }

    /// The inverse. `None` for anything this binary does not say itself.
    pub(crate) fn parse(s: &str) -> Option<Msg> {
        [
            Msg::UserAdded,
            Msg::UserSaved,
            Msg::UserRemoved,
            Msg::KeySaved,
            Msg::KeyRemoved,
            Msg::AppAdded,
            Msg::AppSaved,
            Msg::AppRemoved,
            Msg::ScopeAdded,
            Msg::ScopeSaved,
            Msg::ScopeRemoved,
            Msg::ScopeMoved,
            Msg::GroupAdded,
            Msg::GroupSaved,
            Msg::GroupRemoved,
            Msg::DeniedAdded,
            Msg::DeniedRemoved,
            Msg::SettingsSaved,
        ]
        .into_iter()
        .find(|m| m.key() == s)
    }

    pub(crate) fn text(self, lang: Lang) -> &'static str {
        t(
            lang,
            match self {
                Msg::UserAdded => K::MsgUserAdded,
                Msg::UserSaved => K::MsgUserSaved,
                Msg::UserRemoved => K::MsgUserRemoved,
                Msg::KeySaved => K::MsgKeySaved,
                Msg::KeyRemoved => K::MsgKeyRemoved,
                Msg::AppAdded => K::MsgAppAdded,
                Msg::AppSaved => K::MsgAppSaved,
                Msg::AppRemoved => K::MsgAppRemoved,
                Msg::ScopeAdded => K::MsgScopeAdded,
                Msg::ScopeSaved => K::MsgScopeSaved,
                Msg::ScopeRemoved => K::MsgScopeRemoved,
                Msg::ScopeMoved => K::MsgScopeMoved,
                Msg::GroupAdded => K::MsgGroupAdded,
                Msg::GroupSaved => K::MsgGroupSaved,
                Msg::GroupRemoved => K::MsgGroupRemoved,
                Msg::SettingsSaved => K::MsgSettingsSaved,
                Msg::DeniedAdded => K::MsgDeniedAdded,
                Msg::DeniedRemoved => K::MsgDeniedRemoved,
            },
        )
    }
}
