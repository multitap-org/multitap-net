#include "net_trust.h"

#include <cstdio>
#include <cstring>
#include <atomic>
#include <ctime>
#include <mutex>

#include "host_fs.h"
#include "host_log.h"
#include "monocypher.h"
#include "settings_file.h"

static constexpr const char* DEVICE_PREFIX = "device:";

// net_trust_file_lock: one paired-devices file per process, written by both
// sides of the device (see net_trust.h).
static std::mutex trust_file_mutex;
static std::atomic<uint32_t> trust_generation{1};

void net_trust_file_lock()
{
    trust_file_mutex.lock();
}

void net_trust_file_unlock()
{
    trust_file_mutex.unlock();
}

uint32_t net_trust_generation()
{
    return trust_generation.load();
}

static constexpr const char* CAP_NAMES[NET_CAP_COUNT] = {"gamepad", "stream", "settings", "share"};
static constexpr const char* KIND_NAMES[NET_APP_KIND_COUNT] = {"piccolo", "piccoletto", "piccolino"};

std::string net_caps_name(NetCaps caps)
{
    std::string out;
    for (uint32_t i = 0; i < NET_CAP_COUNT; i++)
    {
        if ((caps & (1u << i)) == 0)
        {
            continue;
        }
        if (!out.empty())
        {
            out += ",";
        }
        out += CAP_NAMES[i];
    }
    return out;
}

static bool is_list_space(char c)
{
    return c == ' ' || c == '\t';
}

bool net_caps_parse(const char* text, NetCaps* caps)
{
    NetCaps result = 0;
    const char* at = text;
    while (*at != '\0')
    {
        while (is_list_space(*at) || *at == ',')
        {
            at++;
        }
        const char* start = at;
        while (*at != '\0' && *at != ',' && !is_list_space(*at))
        {
            at++;
        }
        size_t length = static_cast<size_t>(at - start);
        if (length == 0)
        {
            continue;
        }
        bool known = false;
        for (uint32_t i = 0; i < NET_CAP_COUNT; i++)
        {
            if (std::strlen(CAP_NAMES[i]) == length && std::strncmp(CAP_NAMES[i], start, length) == 0)
            {
                result |= 1u << i;
                known = true;
                break;
            }
        }
        if (!known)
        {
            return false;
        }
    }
    *caps = result;
    return true;
}

bool net_caps_from_level(const char* level, NetCaps* caps)
{
    if (std::strcmp(level, "gamepad") == 0)
    {
        *caps = NET_CAP_GAMEPAD;
        return true;
    }
    if (std::strcmp(level, "stream") == 0)
    {
        *caps = NET_CAP_GAMEPAD | NET_CAP_STREAM;
        return true;
    }
    if (std::strcmp(level, "share") == 0)
    {
        // The old ladder ranked share above stream and below full.
        *caps = NET_CAP_GAMEPAD | NET_CAP_STREAM | NET_CAP_SHARE;
        return true;
    }
    if (std::strcmp(level, "full") == 0 || std::strcmp(level, "owner") == 0)
    {
        *caps = NET_CAPS_ALL;
        return true;
    }
    return false;
}

const char* net_app_kind_name(NetAppKind kind)
{
    uint32_t index = static_cast<uint32_t>(kind);
    return index < NET_APP_KIND_COUNT ? KIND_NAMES[index] : KIND_NAMES[0];
}

bool net_app_kind_parse(const char* name, NetAppKind* kind)
{
    for (uint32_t i = 0; i < NET_APP_KIND_COUNT; i++)
    {
        if (std::strcmp(name, KIND_NAMES[i]) == 0)
        {
            *kind = static_cast<NetAppKind>(i);
            return true;
        }
    }
    return false;
}

static int32_t hex_value(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    return -1;
}

bool net_hex_to_bytes(const char* hex, uint8_t* out, size_t size)
{
    if (std::strlen(hex) != size * 2)
    {
        return false;
    }
    for (size_t i = 0; i < size; i++)
    {
        int32_t high = hex_value(hex[2 * i]);
        int32_t low = hex_value(hex[2 * i + 1]);
        if (high < 0 || low < 0)
        {
            return false;
        }
        out[i] = static_cast<uint8_t>((high << 4) | low);
    }
    return true;
}

void net_bytes_to_hex(const uint8_t* data, size_t size, char* out, size_t capacity)
{
    static constexpr char DIGITS[] = "0123456789abcdef";
    size_t written = 0;
    for (size_t i = 0; i < size && written + 2 < capacity; i++)
    {
        out[written] = DIGITS[data[i] >> 4];
        out[written + 1] = DIGITS[data[i] & 0x0F];
        written += 2;
    }
    if (capacity > 0)
    {
        out[written] = '\0';
    }
}

bool net_identity_load_or_create(const char* path, NetKeypair* identity)
{
    if (host_fs_exists(path))
    {
        SettingsFile file;
        if (settings_file_load(&file, path))
        {
            const char* secret_hex = settings_file_get(&file, "", "secret");
            uint8_t secret[NET_KEY_SIZE];
            if (secret_hex != nullptr && net_hex_to_bytes(secret_hex, secret, sizeof(secret)))
            {
                net_keypair_from_secret(identity, secret);
                crypto_wipe(secret, sizeof(secret));
                return true;
            }
        }
        // Don't replace a file we can't read: that would silently undo every
        // pairing. The user can delete it to start over.
        host_log(LogLevel::error, "Network: %s is unreadable; delete it to make a new device key", path);
        return false;
    }

    if (!net_keypair_generate(identity))
    {
        return false;
    }
    char hex[2 * NET_KEY_SIZE + 1];
    net_bytes_to_hex(identity->secret, NET_KEY_SIZE, hex, sizeof(hex));
    std::string text = "# This device's network key. Keep it private: whoever has it is this device.\n";
    text += "secret = ";
    text += hex;
    text += "\n";
    bool saved = host_fs_write_private_file(path, text.data(), text.size());
    crypto_wipe(hex, sizeof(hex));
    crypto_wipe(text.data(), text.size());
    if (!saved)
    {
        net_keypair_wipe(identity);
        return false;
    }
    host_log(LogLevel::info, "Network: new device key saved in %s", path);
    return true;
}

// One file's devices, appended to `devices` (no duplicates check: callers do that).
static bool load_devices(const char* path, std::vector<NetTrustedDevice>* devices)
{
    SettingsFile file;
    if (!settings_file_load(&file, path))
    {
        return false;
    }
    size_t prefix_length = std::strlen(DEVICE_PREFIX);
    for (size_t i = 0; i < file.sections.size(); i++)
    {
        const char* section = file.sections[i].name.c_str();
        if (std::strncmp(section, DEVICE_PREFIX, prefix_length) != 0)
        {
            continue;
        }
        NetTrustedDevice device;
        if (!net_hex_to_bytes(section + prefix_length, device.key, NET_KEY_SIZE))
        {
            host_log(LogLevel::warning, "Network: %s: [%s] is not a device key, skipped", path, section);
            continue;
        }
        const char* name = settings_file_get(&file, section, "name");
        const char* kind = settings_file_get(&file, section, "kind");
        const char* grants = settings_file_get(&file, section, "grants");
        const char* granted = settings_file_get(&file, section, "granted");
        const char* signed_build = settings_file_get(&file, section, "signed");
        const char* access = settings_file_get(&file, section, "access");   // the ladder, before 2026-11-25
        const char* own = settings_file_get(&file, section, "own");         // before access existed
        const char* paired = settings_file_get(&file, section, "paired");
        device.name = name != nullptr ? name : "";
        if (kind != nullptr && !net_app_kind_parse(kind, &device.kind))
        {
            device.kind = NetAppKind::piccolo;
        }
        if (grants != nullptr)
        {
            if (!net_caps_parse(grants, &device.grants))
            {
                // Unknown names (a newer build's capability, say): the safe side.
                host_log(LogLevel::warning, "Network: %s: [%s] grants \"%s\" unreadable, read as nothing", path,
                         section, grants);
                device.grants = 0;
            }
        }
        else if (access != nullptr)
        {
            if (!net_caps_from_level(access, &device.grants))
            {
                device.grants = 0;
            }
        }
        else if (own != nullptr && std::strcmp(own, "true") == 0)
        {
            device.grants = NET_CAPS_ALL;
        }
        if (granted != nullptr && !net_caps_parse(granted, &device.granted))
        {
            device.granted = 0;
        }
        device.signed_build = signed_build != nullptr && std::strcmp(signed_build, "true") == 0;
        device.paired = paired != nullptr ? paired : "";
        devices->push_back(device);
    }
    return true;
}

bool net_trust_load(NetTrust* trust, const char* path)
{
    trust->devices.clear();
    if (!host_fs_exists(path))
    {
        return true;
    }
    return load_devices(path, &trust->devices);
}

bool net_trust_save(const NetTrust* trust, const char* path)
{
    SettingsFile file;
    for (size_t i = 0; i < trust->devices.size(); i++)
    {
        const NetTrustedDevice* device = &trust->devices[i];
        char hex[2 * NET_KEY_SIZE + 1];
        net_bytes_to_hex(device->key, NET_KEY_SIZE, hex, sizeof(hex));
        std::string section = std::string(DEVICE_PREFIX) + hex;
        settings_file_set(&file, section.c_str(), "name", device->name.c_str());
        settings_file_set(&file, section.c_str(), "kind", net_app_kind_name(device->kind));
        settings_file_set(&file, section.c_str(), "grants", net_caps_name(device->grants).c_str());
        settings_file_set(&file, section.c_str(), "granted", net_caps_name(device->granted).c_str());
        settings_file_set(&file, section.c_str(), "signed", device->signed_build ? "true" : "false");
        settings_file_set(&file, section.c_str(), "paired", device->paired.c_str());
    }
    bool saved = settings_file_save(&file, path, "Paired devices (a device is its key; the name is only shown)");
    trust_generation.fetch_add(1);
    return saved;
}

bool net_trust_merge_old_hosts(NetTrust* trust, const char* path, const char* old_hosts_path)
{
    if (!host_fs_exists(old_hosts_path))
    {
        return true;
    }
    std::vector<NetTrustedDevice> hosts;
    if (!load_devices(old_hosts_path, &hosts))
    {
        host_log(LogLevel::warning, "Network: %s is unreadable; left as it is", old_hosts_path);
        return true;
    }
    for (size_t i = 0; i < hosts.size(); i++)
    {
        if (net_trust_find(trust, hosts[i].key) >= 0)
        {
            continue;
        }
        NetTrustedDevice device = hosts[i];
        // A client's list held no real level (always gamepad): that host
        // grants us what it says next time, and it may use nothing here.
        device.grants = 0;
        device.granted = 0;
        trust->devices.push_back(device);
    }
    if (!net_trust_save(trust, path))
    {
        return false;
    }
    std::string renamed = std::string(old_hosts_path) + ".old";
    if (!host_fs_rename(old_hosts_path, renamed.c_str()))
    {
        host_log(LogLevel::warning, "Network: merged %s but couldn't rename it", old_hosts_path);
    }
    host_log(LogLevel::info, "Network: %s merged into %s", old_hosts_path, path);
    return true;
}

bool net_trust_has_key_id(const NetTrust* trust, const uint8_t* key_id)
{
    for (size_t i = 0; i < trust->devices.size(); i++)
    {
        if (std::memcmp(trust->devices[i].key, key_id, NET_KEY_ID_SIZE) == 0)
        {
            return true;
        }
    }
    return false;
}

int32_t net_trust_find(const NetTrust* trust, const uint8_t* key)
{
    for (size_t i = 0; i < trust->devices.size(); i++)
    {
        if (std::memcmp(trust->devices[i].key, key, NET_KEY_SIZE) == 0)
        {
            return static_cast<int32_t>(i);
        }
    }
    return -1;
}

static std::string today()
{
    std::time_t now = std::time(nullptr);
    // std::localtime isn't thread-safe; pairing runs on the main thread only.
    std::tm* local = std::localtime(&now);
    char text[16] = "";
    if (local != nullptr)
    {
        std::strftime(text, sizeof(text), "%Y-%m-%d", local);
    }
    return text;
}

// A name that came off the wire (or goes into a file): cut to
// NET_DEVICE_NAME_MAX at a UTF-8 boundary, control characters (line breaks
// included) replaced by '_'. Other bytes, UTF-8 included, stay as they are.
std::string net_name_clean(const char* name)
{
    std::string out;
    size_t length = std::strlen(name);
    if (length > NET_DEVICE_NAME_MAX)
    {
        length = NET_DEVICE_NAME_MAX;
        while (length > 0 && (static_cast<uint8_t>(name[length]) & 0xC0) == 0x80)
        {
            length--;
        }
    }
    for (size_t i = 0; i < length; i++)
    {
        uint8_t c = static_cast<uint8_t>(name[i]);
        out.push_back(c < 0x20 || c == 0x7F ? '_' : name[i]);
    }
    return out;
}

// Names are shown on screens and written as one line of a settings file: the
// cleaned name, brackets replaced too (they'd look like section headers).
static std::string clean_name(const char* name)
{
    std::string out = net_name_clean(name);
    for (size_t i = 0; i < out.size(); i++)
    {
        if (out[i] == '[' || out[i] == ']')
        {
            out[i] = '_';
        }
    }
    return out;
}

uint32_t net_trust_add(NetTrust* trust, const uint8_t* key, const char* name)
{
    int32_t found = net_trust_find(trust, key);
    if (found >= 0)
    {
        NetTrustedDevice* device = &trust->devices[static_cast<size_t>(found)];
        device->name = clean_name(name);
        device->paired = today();
        return static_cast<uint32_t>(found);
    }
    NetTrustedDevice device;
    std::memcpy(device.key, key, NET_KEY_SIZE);
    device.name = clean_name(name);
    device.paired = today();
    trust->devices.push_back(device);
    return static_cast<uint32_t>(trust->devices.size() - 1);
}

bool net_trust_rename(NetTrust* trust, uint32_t index, const char* name)
{
    if (index >= trust->devices.size())
    {
        return false;
    }
    std::string cleaned = clean_name(name);
    if (cleaned.empty() || cleaned == trust->devices[index].name)
    {
        return false;
    }
    trust->devices[index].name = cleaned;
    return true;
}

void net_trust_remove(NetTrust* trust, uint32_t index)
{
    if (index < trust->devices.size())
    {
        trust->devices.erase(trust->devices.begin() + static_cast<std::ptrdiff_t>(index));
    }
}
