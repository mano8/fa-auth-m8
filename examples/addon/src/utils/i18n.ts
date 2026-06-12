export type Locale = 'en' | 'fr' | 'es';

const authLabels = {
  en: {
    apiKey: 'API Key',
    apiKeyWarning:
      'API keys are long-lived credentials stored in chrome.storage.local. Prefer OAuth or password for interactive use. Use API keys only from secured automation environments.',
    email: 'Email',
    invalidApiKey: 'Invalid or expired API key.',
    invalidCredentials: 'Invalid credentials.',
    loginFailed: 'Login failed. Check backend connectivity.',
    logout: 'Logout',
    oauth: 'OAuth',
    oauthUnavailable: 'OAuth unavailable.',
    opening: 'Opening...',
    password: 'Password',
    pasteApiKey: 'paste your API key',
    signedInWithApiKey: 'Signed in with API Key',
    signIn: 'Sign in',
    signInFailedUnreadableToken: 'Sign-in failed: token could not be read.',
    signInWithOAuth: 'Sign in with OAuth',
    signingIn: 'Signing in...',
    startOAuthFailed: 'Failed to start OAuth. Check backend connectivity.',
    testApi: 'Test API',
    testing: 'Testing...',
    useApiKey: 'Use API Key',
    verificationFailed: 'Verification failed. Check backend connectivity.',
    verifying: 'Verifying...',
    googleOAuthDescription:
      'Sign in via Google. A browser tab will open for consent, then close automatically.',
  },
  fr: {
    apiKey: 'Clé API',
    apiKeyWarning:
      'Les clés API sont des identifiants de longue durée stockés dans chrome.storage.local. Préférez OAuth ou le mot de passe pour une utilisation interactive. Utilisez les clés API uniquement depuis des environnements automatisés sécurisés.',
    email: 'E-mail',
    invalidApiKey: 'Clé API invalide ou expirée.',
    invalidCredentials: 'Identifiants invalides.',
    loginFailed: 'Connexion impossible. Vérifiez la connectivité au backend.',
    logout: 'Déconnexion',
    oauth: 'OAuth',
    oauthUnavailable: 'OAuth indisponible.',
    opening: 'Ouverture...',
    password: 'Mot de passe',
    pasteApiKey: 'collez votre clé API',
    signedInWithApiKey: 'Connecté avec une clé API',
    signIn: 'Se connecter',
    signInFailedUnreadableToken: 'Échec de connexion : le jeton est illisible.',
    signInWithOAuth: 'Se connecter avec OAuth',
    signingIn: 'Connexion...',
    startOAuthFailed: 'Impossible de démarrer OAuth. Vérifiez la connectivité au backend.',
    testApi: "Tester l'API",
    testing: 'Test...',
    useApiKey: 'Utiliser la clé API',
    verificationFailed: 'Vérification impossible. Vérifiez la connectivité au backend.',
    verifying: 'Vérification...',
    googleOAuthDescription:
      "Connectez-vous via Google. Un onglet du navigateur s'ouvrira pour le consentement, puis se fermera automatiquement.",
  },
  es: {
    apiKey: 'Clave API',
    apiKeyWarning:
      'Las claves API son credenciales de larga duración almacenadas en chrome.storage.local. Prefiera OAuth o contraseña para el uso interactivo. Use claves API solo desde entornos de automatización seguros.',
    email: 'Correo electrónico',
    invalidApiKey: 'Clave API inválida o caducada.',
    invalidCredentials: 'Credenciales inválidas.',
    loginFailed: 'Error de inicio de sesión. Compruebe la conectividad con el backend.',
    logout: 'Cerrar sesión',
    oauth: 'OAuth',
    oauthUnavailable: 'OAuth no disponible.',
    opening: 'Abriendo...',
    password: 'Contraseña',
    pasteApiKey: 'pegue su clave API',
    signedInWithApiKey: 'Sesión iniciada con clave API',
    signIn: 'Iniciar sesión',
    signInFailedUnreadableToken: 'Error de inicio de sesión: no se pudo leer el token.',
    signInWithOAuth: 'Iniciar sesión con OAuth',
    signingIn: 'Iniciando sesión...',
    startOAuthFailed: 'No se pudo iniciar OAuth. Compruebe la conectividad con el backend.',
    testApi: 'Probar API',
    testing: 'Probando...',
    useApiKey: 'Usar clave API',
    verificationFailed: 'Error de verificación. Compruebe la conectividad con el backend.',
    verifying: 'Verificando...',
    googleOAuthDescription:
      'Inicie sesión con Google. Se abrirá una pestaña del navegador para el consentimiento y luego se cerrará automáticamente.',
  },
} as const;

export type TranslationKey = keyof typeof authLabels.en;

function currentLocale(): Locale {
  const language = navigator.language.toLowerCase();
  if (language.startsWith('fr')) return 'fr';
  if (language.startsWith('es')) return 'es';
  return 'en';
}

export function t(key: TranslationKey): string {
  return authLabels[currentLocale()][key];
}
