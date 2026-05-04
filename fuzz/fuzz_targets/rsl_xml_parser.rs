//! Q4.11 - fuzz harness for the RSL `/licenses.xml` parser path.
//!
//! Feeds arbitrary bytes through the same `quick-xml` reader/writer
//! pair the production RSL emitter (G4.7) is expected to use. Goal:
//!
//!   - No panics on any input.
//!   - No infinite loops (libFuzzer's per-input timeout catches these).
//!   - No unbounded memory growth (libFuzzer's RSS budget catches these).
//!
//! Once G4.7 ships a public `parse_rsl(bytes) -> Result<Rsl, _>`
//! function, repoint the harness to call it. The current body
//! exercises the underlying `quick-xml` reader so the fuzz machinery
//! is functional today.

#![no_main]

use libfuzzer_sys::fuzz_target;
use quick_xml::events::Event;
use quick_xml::reader::Reader;

fuzz_target!(|data: &[u8]| {
    let mut reader = Reader::from_reader(data);
    reader.config_mut().trim_text(true);
    reader.config_mut().expand_empty_elements = false;

    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut depth: u32 = 0;
    // Cap the work this harness does per input so an adversarial
    // input that keeps yielding well-formed events does not spin
    // forever. `quick-xml` itself does not loop, but a fuzzer that
    // generates very long well-formed strings can keep us busy past
    // libFuzzer's per-input deadline. Capping events at 100k is
    // generous (real licenses.xml documents top out around 5k events)
    // while keeping the per-input wall-time bounded.
    const MAX_EVENTS: usize = 100_000;
    let mut events: usize = 0;
    loop {
        if events >= MAX_EVENTS {
            break;
        }
        events += 1;
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(_)) => {
                depth = depth.saturating_add(1);
            }
            Ok(Event::End(_)) => {
                depth = depth.saturating_sub(1);
            }
            Ok(Event::Empty(_))
            | Ok(Event::Text(_))
            | Ok(Event::CData(_))
            | Ok(Event::Comment(_))
            | Ok(Event::Decl(_))
            | Ok(Event::PI(_))
            | Ok(Event::DocType(_)) => {}
            Ok(Event::Eof) => break,
            Err(_) => {
                // Malformed input is fine; we are fuzzing the parser
                // for panics, not for parse correctness.
                break;
            }
        }
        buf.clear();
    }
    // Write an assertion-free use of `depth` so the optimizer cannot
    // drop the read loop (which would defeat the fuzzer).
    std::hint::black_box(depth);
});
