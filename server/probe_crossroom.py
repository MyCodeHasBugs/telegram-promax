"""
跨房间投递攻击 probe:
  - victim 加入 roomB, 拿 sid V
  - attacker 加入 roomA, 拿 sid A
  - attacker 给 V 发 relay_slice target=V
  - 预期: server 踢 attacker (kick + disconnect), V 收不到 chat_slice
"""
import socketio, asyncio

async def main():
    victim    = socketio.AsyncClient()
    attacker  = socketio.AsyncClient()

    victim_slices  = []
    attacker_se   = []
    attacker_discon = False

    @victim.on("chat_slice")
    def _v_cs(msg): victim_slices.append(msg)
    @victim.on("server_event")
    def _v_se(msg): print(f"[VICTIM] SE: {msg}")

    @attacker.on("server_event")
    def _a_se(msg): attacker_se.append(msg); print(f"[ATTACK] SE: {msg}")
    @attacker.on("disconnect")
    def _a_dc(): nonlocal attacker_discon; attacker_discon = True; print("[ATTACK] disconnected by server")
    @attacker.on("auth_response")
    def _a_ar(msg): print(f"[ATTACK] auth resp sid={msg.get('sid','-')} room={msg.get('room','-')}")
    attacker_sid = [None]
    @attacker.on("auth_response")
    def _a_ar2(msg): attacker_sid[0] = msg.get("sid")
    @victim.on("auth_response")
    def _v_ar(msg): print(f"[VICTIM] auth resp sid={msg.get('sid','-')} room={msg.get('room','-')}")
    victim_sid = [None]
    @victim.on("auth_response")
    def _v_ar2(msg): victim_sid[0] = msg.get("sid")

    # ws:// (server 临时启 plain ws 模式跑 probe)
    await victim.connect("ws://127.0.0.1:32759", transports=["websocket"])
    await attacker.connect("ws://127.0.0.1:32759", transports=["websocket"])

    # 1) victim auth (room B)
    import blake3
    v_epub = "V" + "k"*43 + "="
    a_epub = "A" + "k"*43 + "="
    await victim.emit("auth", {"epub": v_epub, "room": "roomB",
                                "blake3": blake3.blake3(v_epub.encode()).hexdigest()})
    # 2) attacker auth (room A)
    await attacker.emit("auth", {"epub": a_epub, "room": "roomA",
                                 "blake3": blake3.blake3(a_epub.encode()).hexdigest()})

    await asyncio.sleep(1.2)
    print(f"--- both authed, attacker={attacker_sid[0]}, victim={victim_sid[0]} ---")

    # 真正的跨房间投递: attacker 在 roomA, 给 victim sid (在 roomB) 发 slice
    print(f"\n--- attacker 给 cross-room victim 发 slice target={victim_sid[0]} ---")
    await attacker.emit("relay_slice", {"target": victim_sid[0], "data": "Qk9HT1M="})
    await asyncio.sleep(1.5)

    print("\n--- 验证结果 ---")
    print(f"attacker_se: {attacker_se}")
    print(f"attacker disconnected: {attacker_discon}")
    print(f"victim_slices (期望 0): {len(victim_slices)}")

    if victim_slices:
        print("\n!!!!!!!! BAD: victim 收到 attacker 的 slice !!!!!!!!")
    else:
        print("\n+++++++ OK: victim 没收到 attacker 的 slice +++++++")

    try: await attacker.disconnect()
    except: pass
    try: await victim.disconnect()
    except: pass
    await asyncio.sleep(0.3)

asyncio.run(main())
