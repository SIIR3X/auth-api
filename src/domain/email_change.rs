//! Email change flow: the order of its steps, apart from its Redis storage.

use serde::{Deserialize, Serialize};

/// Where a flow stands. Stored in Redis by name: renaming a variant strands
/// the flows in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowStep {
    /// OTP sent to the current email; waiting for the user to confirm it.
    CurrentVerify,
    /// Current email confirmed; waiting for the user to submit a new address.
    NewSubmit,
    /// OTP sent to the new email; waiting for the user to confirm it.
    NewVerify,
}

/// What the user just did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowEvent {
    CurrentConfirmed,
    NewAddressSubmitted,
    NewConfirmed,
}

/// Where an event takes a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    To(FlowStep),
    Done,
}

impl FlowStep {
    /// The transition `event` makes from this step, or `None` when the event
    /// does not belong to it: a step can be neither skipped nor replayed.
    pub fn after(self, event: FlowEvent) -> Option<Transition> {
        match (self, event) {
            (FlowStep::CurrentVerify, FlowEvent::CurrentConfirmed) => {
                Some(Transition::To(FlowStep::NewSubmit))
            }
            (FlowStep::NewSubmit, FlowEvent::NewAddressSubmitted) => {
                Some(Transition::To(FlowStep::NewVerify))
            }
            (FlowStep::NewVerify, FlowEvent::NewConfirmed) => Some(Transition::Done),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STEPS: [FlowStep; 3] = [
        FlowStep::CurrentVerify,
        FlowStep::NewSubmit,
        FlowStep::NewVerify,
    ];
    const EVENTS: [FlowEvent; 3] = [
        FlowEvent::CurrentConfirmed,
        FlowEvent::NewAddressSubmitted,
        FlowEvent::NewConfirmed,
    ];

    #[test]
    fn each_step_accepts_exactly_its_own_event() {
        let expected = [
            Some(Transition::To(FlowStep::NewSubmit)),
            Some(Transition::To(FlowStep::NewVerify)),
            Some(Transition::Done),
        ];
        for (s, step) in STEPS.into_iter().enumerate() {
            for (e, event) in EVENTS.into_iter().enumerate() {
                let transition = step.after(event);
                if s == e {
                    assert_eq!(transition, expected[s], "{step:?} on {event:?}");
                } else {
                    assert_eq!(transition, None, "{step:?} must refuse {event:?}");
                }
            }
        }
    }

    #[test]
    fn steps_are_stored_under_stable_names() {
        for (step, name) in
            STEPS
                .into_iter()
                .zip(["\"current_verify\"", "\"new_submit\"", "\"new_verify\""])
        {
            assert_eq!(serde_json::to_string(&step).unwrap(), name);
            assert_eq!(serde_json::from_str::<FlowStep>(name).unwrap(), step);
        }
    }
}
