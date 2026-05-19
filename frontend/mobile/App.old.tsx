import React, { useEffect, useState } from 'react';
import { View, Text, TouchableOpacity, ScrollView, Alert } from 'react-native';
import axios from 'axios';

const API = 'http://10.0.2.2:5000/api'; // Android emulator localhost

export default function App() {
  const [servers, setServers] = useState<any[]>([]);
  const [status, setStatus] = useState('Disconnected');

  useEffect(() => {
    axios.post(`${API}/auth`, { username: 'demo', password: 'demo' }).then(() => {
      axios.get(`${API}/servers`).then(r => setServers(r.data));
    });
  }, []);

  const connect = async (s:any) => {
    setStatus('Fetching config...');
    const cfg = await axios.get(`${API}/config/${s.id}`);
    // On Android, launch WireGuard app via intent or use react-native-wireguard
    Alert.alert('Config Ready', `Copy this to WireGuard app:

${cfg.data.substring(0,120)}...`);
    setStatus(`Connected (simulated) to ${s.name}`);
  };

  return (
    <View style={{ flex:1, backgroundColor:'#0a0a0a', padding:20, paddingTop:60 }}>
      <Text style={{ color:'white', fontSize:28, fontWeight:'bold' }}>FortiClone VPN</Text>
      <Text style={{ color:'#22c55e', marginVertical:10 }}>{status}</Text>
      <ScrollView>
        {servers.map(s => (
          <View key={s.id} style={{ backgroundColor:'#171717', padding:16, borderRadius:12, marginBottom:12 }}>
            <Text style={{ color:'white', fontSize:18, fontWeight:'600' }}>{s.name}</Text>
            <Text style={{ color:'#9ca3af' }}>{s.country} • {s.type} • {s.latencyMs}ms</Text>
            <TouchableOpacity onPress={()=>connect(s)} style={{ backgroundColor:'#2563eb', padding:12, borderRadius:8, marginTop:10 }}>
              <Text style={{ color:'white', textAlign:'center', fontWeight:'600' }}>Connect</Text>
            </TouchableOpacity>
          </View>
        ))}
      </ScrollView>
    </View>
  );
}
