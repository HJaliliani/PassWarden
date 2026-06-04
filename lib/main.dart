import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:cryptography/cryptography.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:file_picker/file_picker.dart';
import 'package:file_saver/file_saver.dart';
import 'dart:async';

void main() {
  runApp(const PasswordManagerApp());
}

class PasswordManagerApp extends StatelessWidget {
  const PasswordManagerApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Zero-Knowledge Passwords',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.deepPurple,
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      home: const AuthScreen(),
    );
  }
}

// ==========================================
// CRYPTO ENGINE (AES-256 & PBKDF2 SHA-256)
// ==========================================
class CryptoEngine {
  static Future<SecretKey> deriveKey(String password, List<int> salt) async {
    final pbkdf2 = Pbkdf2(
      macAlgorithm: Hmac.sha256(),
      iterations: 100000,
      bits: 256,
    );

    return await pbkdf2.deriveKeyFromPassword(
      password: password,
      nonce: salt,
    );
  }

  static Future<String> encryptVault(String vaultJson, SecretKey key) async {
    final algorithm = AesGcm.with256bits();

    final secretBox = await algorithm.encrypt(
      utf8.encode(vaultJson),
      secretKey: key,
    );

    final encryptedEnvelope = {
      'nonce': base64Encode(secretBox.nonce),
      'mac': base64Encode(secretBox.mac.bytes),
      'ciphertext': base64Encode(secretBox.cipherText),
    };

    return jsonEncode(encryptedEnvelope);
  }

  static Future<String> decryptVault(String encryptedEnvelopeJson, SecretKey key) async {
    final envelope = jsonDecode(encryptedEnvelopeJson);
    final algorithm = AesGcm.with256bits();

    final secretBox = SecretBox(
      base64Decode(envelope['ciphertext']),
      nonce: base64Decode(envelope['nonce']),
      mac: Mac(base64Decode(envelope['mac'])),
    );

    final clearTextBytes = await algorithm.decrypt(
      secretBox,
      secretKey: key,
    );

    return utf8.decode(clearTextBytes);
  }

  static List<int> generateSalt() {
    final random = Random.secure();
    return List<int>.generate(16, (i) => random.nextInt(256));
  }
}

// ==========================================
// TOTP ENGINE
// ==========================================
class TotpEngine {
  static Uint8List _base32Decode(String base32) {
    const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    base32 = base32.replaceAll('=', '').toUpperCase();
    var bits = '';
    for (var i = 0; i < base32.length; i++) {
      final val = base32Chars.indexOf(base32[i]);
      if (val == -1) continue;
      bits += val.toRadixString(2).padLeft(5, '0');
    }

    final bytes = <int>[];
    for (var i = 0; i + 8 <= bits.length; i += 8) {
      bytes.add(int.parse(bits.substring(i, i + 8), radix: 2));
    }
    return Uint8List.fromList(bytes);
  }

  static Future<String> generateCode(String secret) async {
    try {
      final keyBytes = _base32Decode(secret);
      if (keyBytes.isEmpty) return 'INVALID';

      final time = (DateTime.now().millisecondsSinceEpoch ~/ 1000) ~/ 30;
      final timeBytes = Uint8List(8);
      for (var i = 7; i >= 0; i--) {
        timeBytes[i] = (time >> (8 * (7 - i))) & 0xff;
      }

      final hmac = Hmac.sha1();
      final mac = await hmac.calculateMac(
        timeBytes,
        secretKey: SecretKey(keyBytes),
      );

      final macBytes = mac.bytes;
      final offset = macBytes[macBytes.length - 1] & 0xf;

      final binary = ((macBytes[offset] & 0x7f) << 24) |
      ((macBytes[offset + 1] & 0xff) << 16) |
      ((macBytes[offset + 2] & 0xff) << 8) |
      (macBytes[offset + 3] & 0xff);

      return (binary % 1000000).toString().padLeft(6, '0');
    } catch (e) {
      return 'ERROR';
    }
  }
}

// ==========================================
// AUTHENTICATION SCREEN
// ==========================================
class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key});

  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  final _passwordController = TextEditingController();
  bool _isNewUser = true;
  bool _isLoading = true;
  String _errorMessage = '';

  @override
  void initState() {
    super.initState();
    _checkExistingVault();
  }

  Future<void> _checkExistingVault() async {
    final prefs = await SharedPreferences.getInstance();
    setState(() {
      _isNewUser = !prefs.containsKey('vault_data');
      _isLoading = false;
    });
  }

  Future<void> _authenticate() async {
    setState(() {
      _isLoading = true;
      _errorMessage = '';
    });

    final password = _passwordController.text;
    final prefs = await SharedPreferences.getInstance();

    try {
      SecretKey key;
      String decryptedVaultJson = '[]';

      if (_isNewUser) {
        final salt = CryptoEngine.generateSalt();
        await prefs.setString('vault_salt', base64Encode(salt));
        key = await CryptoEngine.deriveKey(password, salt);

        final encryptedVault = await CryptoEngine.encryptVault('[]', key);
        await prefs.setString('vault_data', encryptedVault);
      } else {
        final saltBase64 = prefs.getString('vault_salt')!;
        final salt = base64Decode(saltBase64);
        key = await CryptoEngine.deriveKey(password, salt);

        final encryptedVault = prefs.getString('vault_data')!;
        decryptedVaultJson = await CryptoEngine.decryptVault(encryptedVault, key);
      }

      if (mounted) {
        Navigator.of(context).pushReplacement(
          MaterialPageRoute(
            builder: (_) => VaultScreen(
              encryptionKey: key,
              initialVaultData: decryptedVaultJson,
            ),
          ),
        );
      }
    } catch (e) {
      setState(() {
        _errorMessage = 'Authentication failed. Incorrect password?';
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_isLoading) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }

    return Scaffold(
      appBar: AppBar(title: const Text('Zero-Knowledge Vault')),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 400),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Icon(Icons.lock_outline, size: 64, color: Theme.of(context).colorScheme.primary),
                const SizedBox(height: 32),
                Text(
                  _isNewUser ? 'Create Master Password' : 'Enter Master Password',
                  style: Theme.of(context).textTheme.headlineSmall,
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 16),
                TextField(
                  controller: _passwordController,
                  obscureText: true,
                  decoration: const InputDecoration(
                    border: OutlineInputBorder(),
                    labelText: 'Master Password',
                  ),
                  onSubmitted: (_) => _authenticate(),
                ),
                if (_errorMessage.isNotEmpty) ...[
                  const SizedBox(height: 16),
                  Text(_errorMessage, style: const TextStyle(color: Colors.red)),
                ],
                const SizedBox(height: 24),
                ElevatedButton(
                  onPressed: _authenticate,
                  child: Text(_isNewUser ? 'Setup Vault' : 'Unlock Vault'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

// ==========================================
// VAULT SCREEN (Main Password List)
// ==========================================
class VaultScreen extends StatefulWidget {
  final SecretKey encryptionKey;
  final String initialVaultData;

  const VaultScreen({
    super.key,
    required this.encryptionKey,
    required this.initialVaultData,
  });

  @override
  State<VaultScreen> createState() => _VaultScreenState();
}

class _VaultScreenState extends State<VaultScreen> {
  List<dynamic> _vault = [];
  String _searchQuery = '';

  @override
  void initState() {
    super.initState();
    _vault = jsonDecode(widget.initialVaultData);
  }

  Future<void> _saveVault() async {
    final prefs = await SharedPreferences.getInstance();
    final vaultJson = jsonEncode(_vault);
    final encryptedVault = await CryptoEngine.encryptVault(vaultJson, widget.encryptionKey);
    await prefs.setString('vault_data', encryptedVault);
  }

  void _addCredential(Map<String, String> credential) {
    setState(() {
      _vault.add(credential);
    });
    _saveVault();
  }

  void _updateCredential(dynamic oldCred, Map<String, String> newCred) {
    setState(() {
      final index = _vault.indexOf(oldCred);
      if (index != -1) {
        _vault[index] = newCred;
      }
    });
    _saveVault();
  }

  Future<void> _editCredential(dynamic cred) async {
    final result = await showDialog<Map<String, String>>(
      context: context,
      builder: (context) => AddCredentialDialog(existingCred: Map<String, String>.from(cred)),
    );
    if (result != null) {
      _updateCredential(cred, result);
    }
  }

  void _deleteCredential(dynamic cred) {
    setState(() {
      _vault.remove(cred);
    });
    _saveVault();
  }

  Future<void> _copyTotpOnly(dynamic cred) async {
    final seed = cred['totpSeed'];
    if (seed == null || seed.toString().isEmpty) return;
    final code = await TotpEngine.generateCode(seed.toString());
    await Clipboard.setData(ClipboardData(text: code));
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('2FA Code copied!')));
    }
  }

  Future<void> _copyPasswordAndTotp(dynamic cred) async {
    final seed = cred['totpSeed'];
    final password = cred['password'] ?? '';
    if (seed == null || seed.toString().isEmpty) return;
    final code = await TotpEngine.generateCode(seed.toString());
    await Clipboard.setData(ClipboardData(text: '$password$code'));
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Password + 2FA copied!')));
    }
  }

  Future<String?> _promptForPassword(String title) {
    final controller = TextEditingController();
    return showDialog<String>(
        context: context,
        builder: (context) => AlertDialog(
          title: Text(title),
          content: TextField(
            controller: controller,
            obscureText: true,
            decoration: const InputDecoration(labelText: 'Password'),
          ),
          actions: [
            TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
            ElevatedButton(onPressed: () => Navigator.pop(context, controller.text), child: const Text('Confirm')),
          ],
        )
    );
  }

  Future<void> _exportVault() async {
    final password = await _promptForPassword('Enter Master Password to Export');
    if (password == null || password.isEmpty) return;

    try {
      final exportSalt = CryptoEngine.generateSalt();
      final exportKey = await CryptoEngine.deriveKey(password, exportSalt);
      final vaultJson = jsonEncode(_vault);
      final encryptedExport = await CryptoEngine.encryptVault(vaultJson, exportKey);

      final exportData = jsonEncode({
        'salt': base64Encode(exportSalt),
        'vault_data': encryptedExport,
      });

      final bytes = Uint8List.fromList(utf8.encode(exportData));

      await FileSaver.instance.saveFile(
        name: 'vault_export.json',
        bytes: bytes,
      );

      if (mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Vault exported successfully!')));
    } catch (e) {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Export failed: $e')));
    }
  }

  Future<void> _importVault() async {
    try {
      FilePickerResult? result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: ['json'],
        withData: true,
      );

      if (result != null && result.files.single.bytes != null) {
        final fileContent = utf8.decode(result.files.single.bytes!);
        final importData = jsonDecode(fileContent);

        if (!importData.containsKey('salt') || !importData.containsKey('vault_data')) {
          throw Exception('Invalid vault file format.');
        }

        final salt = base64Decode(importData['salt']);
        final encryptedVault = importData['vault_data'];

        final password = await _promptForPassword('Enter Password for Imported Vault');
        if (password == null || password.isEmpty) return;

        final importKey = await CryptoEngine.deriveKey(password, salt);
        final decryptedJson = await CryptoEngine.decryptVault(encryptedVault, importKey);

        final List<dynamic> importedVault = jsonDecode(decryptedJson);
        setState(() {
          _vault.addAll(importedVault);
        });
        await _saveVault();
        if (mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Vault imported successfully!')));
      }
    } catch (e) {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Import failed (Wrong password or corrupted file).')));
    }
  }

  Future<void> _changeMasterPassword() async {
    final currentPassword = await _promptForPassword('Enter Current Master Password');
    if (currentPassword == null || currentPassword.isEmpty) return;

    final prefs = await SharedPreferences.getInstance();
    final currentSalt = base64Decode(prefs.getString('vault_salt')!);
    final testKey = await CryptoEngine.deriveKey(currentPassword, currentSalt);
    try {
      await CryptoEngine.decryptVault(prefs.getString('vault_data')!, testKey);
    } catch(e) {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Incorrect current password!')));
      return;
    }

    final newPassword = await _promptForPassword('Enter New Master Password');
    if (newPassword == null || newPassword.isEmpty) return;

    final newSalt = CryptoEngine.generateSalt();
    final newKey = await CryptoEngine.deriveKey(newPassword, newSalt);

    final vaultJson = jsonEncode(_vault);
    final encryptedVault = await CryptoEngine.encryptVault(vaultJson, newKey);

    await prefs.setString('vault_salt', base64Encode(newSalt));
    await prefs.setString('vault_data', encryptedVault);

    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('Password changed! Please log in again.')));
      _lock();
    }
  }

  void _lock() {
    Navigator.of(context).pushReplacement(
      MaterialPageRoute(builder: (_) => const AuthScreen()),
    );
  }

  @override
  Widget build(BuildContext context) {
    final filteredVault = _vault.where((cred) {
      final title = (cred['title'] ?? '').toString().toLowerCase();
      final url = (cred['url'] ?? '').toString().toLowerCase();
      final desc = (cred['description'] ?? '').toString().toLowerCase();
      final query = _searchQuery.toLowerCase();
      return title.contains(query) || url.contains(query) || desc.contains(query);
    }).toList();

    return Scaffold(
      appBar: AppBar(
        title: const Text('My Passwords'),
        actions: [
          // This is the menu where Export, Import, and Change Password live
          PopupMenuButton<String>(
            onSelected: (value) {
              if (value == 'export') _exportVault();
              if (value == 'import') _importVault();
              if (value == 'change_pwd') _changeMasterPassword();
              if (value == 'lock') _lock();
            },
            itemBuilder: (BuildContext context) => [
              const PopupMenuItem(value: 'export', child: Text('Export Vault')),
              const PopupMenuItem(value: 'import', child: Text('Import Vault')),
              const PopupMenuItem(value: 'change_pwd', child: Text('Change Master Password')),
              const PopupMenuItem(value: 'lock', child: Text('Lock Vault')),
            ],
          ),
        ],
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.all(16.0),
            child: TextField(
              decoration: const InputDecoration(
                labelText: 'Search by Title or URL',
                prefixIcon: Icon(Icons.search),
                border: OutlineInputBorder(),
              ),
              onChanged: (value) {
                setState(() {
                  _searchQuery = value;
                });
              },
            ),
          ),
          Expanded(
            child: _vault.isEmpty
                ? const Center(child: Text('Your vault is empty. Add a password!'))
                : filteredVault.isEmpty
                ? const Center(child: Text('No passwords match your search.'))
                : ListView.builder(
              itemCount: filteredVault.length,
              itemBuilder: (context, index) {
                final cred = filteredVault[index];
                return Card(
                  margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                  child: ListTile(
                    leading: const CircleAvatar(child: Icon(Icons.security)),
                    title: Row(
                      children: [
                        Text(cred['title'] ?? 'Unknown'),
                        if (cred['totpSeed'] != null && cred['totpSeed'].toString().isNotEmpty)
                          Padding(
                            padding: const EdgeInsets.only(left: 8.0),
                            child: Container(
                              padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
                              decoration: BoxDecoration(
                                color: Theme.of(context).colorScheme.primary,
                                borderRadius: BorderRadius.circular(4),
                              ),
                              child: const Text('2FA', style: TextStyle(fontSize: 10, color: Colors.black, fontWeight: FontWeight.bold)),
                            ),
                          ),
                      ],
                    ),
                    subtitle: Text(cred['username'] ?? ''),
                    trailing: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        if (cred['totpSeed'] != null && cred['totpSeed'].toString().isNotEmpty) ...[
                          IconButton(
                            icon: const Icon(Icons.timer, color: Colors.greenAccent),
                            tooltip: 'Copy 2FA Only',
                            onPressed: () => _copyTotpOnly(cred),
                          ),
                          IconButton(
                            icon: const Icon(Icons.password, color: Colors.orangeAccent),
                            tooltip: 'Copy Password + 2FA',
                            onPressed: () => _copyPasswordAndTotp(cred),
                          ),
                        ],
                        IconButton(
                          icon: const Icon(Icons.edit, color: Colors.blueAccent),
                          onPressed: () => _editCredential(cred),
                        ),
                        IconButton(
                          icon: const Icon(Icons.delete, color: Colors.redAccent),
                          onPressed: () => _deleteCredential(cred),
                        ),
                      ],
                    ),
                    onTap: () {
                      _showPasswordDialog(context, cred);
                    },
                  ),
                );
              },
            ),
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () async {
          final result = await showDialog<Map<String, String>>(
            context: context,
            builder: (context) => const AddCredentialDialog(),
          );
          if (result != null) {
            _addCredential(result);
          }
        },
        child: const Icon(Icons.add),
      ),
    );
  }

  void _showPasswordDialog(BuildContext context, Map<String, dynamic> cred) {
    Widget buildRow(String label, String? value) {
      if (value == null || value.isEmpty) return const SizedBox.shrink();
      return Padding(
        padding: const EdgeInsets.only(bottom: 8.0),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(child: Text('$label: $value')),
            IconButton(
              icon: const Icon(Icons.copy, size: 20),
              padding: EdgeInsets.zero,
              constraints: const BoxConstraints(),
              onPressed: () {
                Clipboard.setData(ClipboardData(text: value));
                ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('$label copied!')));
              },
            )
          ],
        ),
      );
    }

    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(cred['title'] ?? ''),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              buildRow('Username', cred['username']),
              buildRow('Password', cred['password']),
              buildRow('URL', cred['url']),
              buildRow('Description', cred['description']),
              if (cred['totpSeed'] != null && cred['totpSeed'].toString().isNotEmpty) ...[
                const SizedBox(height: 16),
                const Text('Authenticator Code (TOTP)', style: TextStyle(fontSize: 12, color: Colors.grey)),
                const SizedBox(height: 8),
                TotpDisplayWidget(secret: cred['totpSeed']),
              ]
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }
}

// ==========================================
// TOTP DISPLAY WIDGET
// ==========================================
class TotpDisplayWidget extends StatefulWidget {
  final String secret;
  const TotpDisplayWidget({super.key, required this.secret});

  @override
  State<TotpDisplayWidget> createState() => _TotpDisplayWidgetState();
}

class _TotpDisplayWidgetState extends State<TotpDisplayWidget> {
  String _code = '------';
  double _progress = 1.0;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    _updateTotp();
    _timer = Timer.periodic(const Duration(seconds: 1), (_) => _updateTotp());
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  Future<void> _updateTotp() async {
    final now = DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final remaining = 30 - (now % 30);
    final newCode = await TotpEngine.generateCode(widget.secret);

    if (mounted) {
      setState(() {
        _code = newCode;
        _progress = remaining / 30.0;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.secondaryContainer,
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: Theme.of(context).colorScheme.outlineVariant),
      ),
      child: Row(
        children: [
          SizedBox(
            width: 24,
            height: 24,
            child: CircularProgressIndicator(
              value: _progress,
              strokeWidth: 2,
              backgroundColor: Theme.of(context).colorScheme.outlineVariant,
            ),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Text(
              _code.length == 6 ? '${_code.substring(0, 3)} ${_code.substring(3, 6)}' : _code,
              style: const TextStyle(fontSize: 18, letterSpacing: 2, fontFamily: 'monospace', fontWeight: FontWeight.bold),
            ),
          ),
          IconButton(
            icon: const Icon(Icons.copy, size: 20),
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(),
            onPressed: () {
              Clipboard.setData(ClipboardData(text: _code.replaceAll(' ', '')));
              ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('TOTP copied!')));
            },
          )
        ],
      ),
    );
  }
}

// ==========================================
// ADD CREDENTIAL DIALOG
// ==========================================
class AddCredentialDialog extends StatefulWidget {
  final Map<String, String>? existingCred;

  const AddCredentialDialog({super.key, this.existingCred});

  @override
  State<AddCredentialDialog> createState() => _AddCredentialDialogState();
}

class _AddCredentialDialogState extends State<AddCredentialDialog> {
  late TextEditingController _titleController;
  late TextEditingController _usernameController;
  late TextEditingController _passwordController;
  late TextEditingController _urlController;
  late TextEditingController _descriptionController;
  late TextEditingController _totpSeedController;

  @override
  void initState() {
    super.initState();
    _titleController = TextEditingController(text: widget.existingCred?['title'] ?? '');
    _usernameController = TextEditingController(text: widget.existingCred?['username'] ?? '');
    _passwordController = TextEditingController(text: widget.existingCred?['password'] ?? '');
    _urlController = TextEditingController(text: widget.existingCred?['url'] ?? '');
    _descriptionController = TextEditingController(text: widget.existingCred?['description'] ?? '');
    _totpSeedController = TextEditingController(text: widget.existingCred?['totpSeed'] ?? '');
  }

  @override
  void dispose() {
    _titleController.dispose();
    _usernameController.dispose();
    _passwordController.dispose();
    _urlController.dispose();
    _descriptionController.dispose();
    _totpSeedController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: Text(widget.existingCred == null ? 'Add Password' : 'Edit Password'),
      content: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: _titleController,
              decoration: const InputDecoration(labelText: 'Title (e.g. Google)'),
            ),
            TextField(
              controller: _usernameController,
              decoration: const InputDecoration(labelText: 'Username/Email'),
            ),
            TextField(
              controller: _passwordController,
              decoration: const InputDecoration(labelText: 'Password'),
              obscureText: true,
            ),
            TextField(
              controller: _urlController,
              decoration: const InputDecoration(labelText: 'Website URL (optional)'),
            ),
            TextField(
              controller: _descriptionController,
              decoration: const InputDecoration(labelText: 'Description (optional)'),
            ),
            TextField(
              controller: _totpSeedController,
              decoration: const InputDecoration(labelText: 'TOTP Seed Key (optional)'),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        ElevatedButton(
          onPressed: () {
            if (_titleController.text.isNotEmpty && _passwordController.text.isNotEmpty) {
              Navigator.of(context).pop({
                'title': _titleController.text,
                'username': _usernameController.text,
                'password': _passwordController.text,
                'url': _urlController.text,
                'description': _descriptionController.text,
                'totpSeed': _totpSeedController.text,
              });
            }
          },
          child: const Text('Save'),
        ),
      ],
    );
  }
}