#include "net_trust.h"

#include <cstdio>
#include <cstring>
#include <ctime>

#include "host_fs.h"
#include "host_log.h"
#include "monocypher.h"
#include "settings_file.h"

static constexpr const char* DEVICE_PREFIX = "device:";

const char* net_access_level_name(NetAccessLevel level)
{
    switch (level)
    {
    case NetAccessLevel::gamepad:
        return "gamepad";
    case NetAccessLevel::stream:
        return "stream";
    case NetAccessLevel::full:
        return "full";
    }
    return "gamepad";
}

bool net_access_level_parse(const char* name, NetAccessLevel* level)
{
    for (uint32_t i = 0; i < NET_ACCESS_LEVEL_COUNT; i++)
    {
        NetAccessLevel candidate = static_cast<NetAccessLevel>(i);
        if (std::strcmp(name, net_access_level_name(candidate)) == 0)
        {
            *level = candidate;
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

bool net_trust_load(NetTrust* trust, const char* path)
{
    trust->devices.clear();
    if (!host_fs_exists(path))
    {
        return true;
    }
    SettingsFile file;
    if (!settings_file_load(&file, path))
    {
        return false;
    }
    size_t prefix_length = std::strlen(DEVICE_PREFIX);
    for (size_t i = 0; i < file.sections.size(); i++)
    {
        const std::string* section = &file.sections[i].name;
        if (section->compare(0, prefix_length, DEVICE_PREFIX) != 0)
        {
            continue;
        }
        NetTrustedDevice device;
        if (!net_hex_to_bytes(section->c_str() + prefix_length, device.key, NET_KEY_SIZE))
        {
            host_log(LogLevel::warning, "Network: %s: [%s] is not a device key, skipped", path, section->c_str());
            continue;
        }
        const char* name = settings_file_get(&file, section->c_str(), "name");
        const char* access = settings_file_get(&file, section->c_str(), "access");
        const char* own = settings_file_get(&file, section->c_str(), "own");   // before access existed
        const char* paired = settings_file_get(&file, section->c_str(), "paired");
        device.name = name != nullptr ? name : "";
        if (access == nullptr || !net_access_level_parse(access, &device.access))
        {
            // Unknown or missing: the least, except an old "own" device.
            device.access = own != nullptr && std::strcmp(own, "true") == 0 ? NetAccessLevel::full : NetAccessLevel::gamepad;
        }
        device.paired = paired != nullptr ? paired : "";
        trust->devices.push_back(device);
    }
    return true;
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
        settings_file_set(&file, section.c_str(), "access", net_access_level_name(device->access));
        settings_file_set(&file, section.c_str(), "paired", device->paired.c_str());
    }
    return settings_file_save(&file, path, "Paired devices (a device is its key; the name is only shown)");
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

// Names are shown on screens and written as one line of a settings file:
// cut to NET_DEVICE_NAME_MAX at a UTF-8 boundary, control characters (line
// breaks included) replaced, brackets too (they'd look like section headers).
static std::string clean_name(const char* name)
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
        out.push_back(c < 0x20 || c == 0x7F || c == '[' || c == ']' ? '_' : name[i]);
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
