//! Finite-state-machine (FSM) orchestrator for multi-agent workflows.
//!
//! A [`FsmWorkflow`] describes a directed graph of states.  Each state names
//! the agent to invoke (`action`) and maps outcome labels to the next state.
//! [`FsmExecution`] drives an in-progress run, recording history and detecting
//! terminal states.

use serde::{
    de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{borrow::Cow, collections::HashMap, fmt};
use thiserror::Error;

const MAX_FSM_STATES: usize = 256;
const MAX_FSM_EDGES: usize = 2_048;
const MAX_FSM_STEPS: usize = 1_024;
const MAX_FSM_TEXT_BYTES: usize = 256;
const MAX_FSM_ACTION_BYTES: usize = 512;
const MAX_FSM_OUTCOME_BYTES: usize = 4_096;
const MAX_FSM_GRAPH_BYTES: usize = 1024 * 1024;
const MAX_FSM_HISTORY_BYTES: usize = 1024 * 1024;

/// A single node in the workflow graph.
#[derive(Debug, Clone, Serialize)]
pub struct FsmState {
    /// Unique name of this state.
    pub name: String,
    /// The agent ID (or action label) to invoke when entering this state.
    pub action: String,
    /// Map of outcome labels to the name of the next state.
    /// If the map is empty, or a result has no matching key, the workflow ends.
    pub transitions: HashMap<String, String>,
}

impl<'de> Deserialize<'de> for FsmState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut budget = DeserializationBudget::default();
        StateSeed {
            budget: &mut budget,
        }
        .deserialize(deserializer)
    }
}

/// A complete workflow graph.
#[derive(Debug, Clone)]
pub struct FsmWorkflow {
    name: String,
    states: HashMap<String, FsmState>,
    initial_state: String,
    max_steps: usize,
}

impl Serialize for FsmWorkflow {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut states = self.states.values().collect::<Vec<_>>();
        states.sort_unstable_by(|left, right| left.name.cmp(&right.name));

        let mut workflow = serializer.serialize_struct("FsmWorkflow", 4)?;
        workflow.serialize_field("name", &self.name)?;
        workflow.serialize_field("states", &states)?;
        workflow.serialize_field("initial_state", &self.initial_state)?;
        workflow.serialize_field("max_steps", &self.max_steps)?;
        workflow.end()
    }
}

impl<'de> Deserialize<'de> for FsmWorkflow {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "FsmWorkflow",
            &["name", "states", "initial_state", "max_steps"],
            WorkflowVisitor,
        )
    }
}

struct WorkflowVisitor;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StructuralField {
    Name,
    States,
    InitialState,
    MaxSteps,
    Action,
    Transitions,
    Unknown,
}

impl<'de> Deserialize<'de> for StructuralField {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StructuralFieldVisitor;

        impl Visitor<'_> for StructuralFieldVisitor {
            type Value = StructuralField;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a bounded FSM field name")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.len() > MAX_FSM_TEXT_BYTES {
                    return Err(E::custom(format_args!(
                        "workflow structural key bytes limit exceeded: limit {}, observed {}",
                        MAX_FSM_TEXT_BYTES,
                        value.len()
                    )));
                }
                Ok(match value {
                    "name" => StructuralField::Name,
                    "states" => StructuralField::States,
                    "initial_state" => StructuralField::InitialState,
                    "max_steps" => StructuralField::MaxSteps,
                    "action" => StructuralField::Action,
                    "transitions" => StructuralField::Transitions,
                    _ => StructuralField::Unknown,
                })
            }

            fn visit_borrowed_str<E>(self, value: &'_ str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(value)
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                self.visit_str(&value)
            }
        }

        deserializer.deserialize_identifier(StructuralFieldVisitor)
    }
}

struct BoundedStringSeed<'a> {
    budget: &'a mut DeserializationBudget,
    dimension: FsmLimitDimension,
}

impl<'de> DeserializeSeed<'de> for BoundedStringSeed<'_> {
    type Value = String;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(BoundedStringVisitor {
            budget: self.budget,
            dimension: self.dimension,
        })
    }
}

struct BoundedStringVisitor<'a> {
    budget: &'a mut DeserializationBudget,
    dimension: FsmLimitDimension,
}

impl Visitor<'_> for BoundedStringVisitor<'_> {
    type Value = String;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded FSM string")
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.add_text::<E>(self.dimension, value)?;
        Ok(value.to_owned())
    }

    fn visit_borrowed_str<E>(self, value: &'_ str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_str(value)
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.budget.add_text::<E>(self.dimension, &value)?;
        Ok(value)
    }
}

impl<'de> Visitor<'de> for WorkflowVisitor {
    type Value = FsmWorkflow;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded FSM workflow")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut name = None;
        let mut states = None;
        let mut initial_state = None;
        let mut max_steps = None;
        let mut budget = DeserializationBudget::default();

        while let Some(field) = map.next_key::<StructuralField>()? {
            match field {
                StructuralField::Name => {
                    if name.is_some() {
                        return Err(de::Error::duplicate_field("name"));
                    }
                    let value = map.next_value_seed(BoundedStringSeed {
                        budget: &mut budget,
                        dimension: FsmLimitDimension::WorkflowNameBytes,
                    })?;
                    name = Some(value);
                }
                StructuralField::States => {
                    if states.is_some() {
                        return Err(de::Error::duplicate_field("states"));
                    }
                    states = Some(map.next_value_seed(StatesSeed {
                        budget: &mut budget,
                    })?);
                }
                StructuralField::InitialState => {
                    if initial_state.is_some() {
                        return Err(de::Error::duplicate_field("initial_state"));
                    }
                    let value = map.next_value_seed(BoundedStringSeed {
                        budget: &mut budget,
                        dimension: FsmLimitDimension::InitialStateBytes,
                    })?;
                    initial_state = Some(value);
                }
                StructuralField::MaxSteps => {
                    if max_steps.is_some() {
                        return Err(de::Error::duplicate_field("max_steps"));
                    }
                    let value = map.next_value::<usize>()?;
                    if value > MAX_FSM_STEPS {
                        return Err(deserialization_limit(
                            FsmLimitDimension::Steps,
                            MAX_FSM_STEPS,
                            value,
                        ));
                    }
                    max_steps = Some(value);
                }
                StructuralField::Action
                | StructuralField::Transitions
                | StructuralField::Unknown => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }

        FsmWorkflow::new(
            name.ok_or_else(|| de::Error::missing_field("name"))?,
            initial_state.ok_or_else(|| de::Error::missing_field("initial_state"))?,
            states.ok_or_else(|| de::Error::missing_field("states"))?,
            max_steps.ok_or_else(|| de::Error::missing_field("max_steps"))?,
        )
        .map_err(de::Error::custom)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut budget = DeserializationBudget::default();
        let name = sequence
            .next_element_seed(BoundedStringSeed {
                budget: &mut budget,
                dimension: FsmLimitDimension::WorkflowNameBytes,
            })?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let states = sequence
            .next_element_seed(StatesSeed {
                budget: &mut budget,
            })?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
        let initial_state = sequence
            .next_element_seed(BoundedStringSeed {
                budget: &mut budget,
                dimension: FsmLimitDimension::InitialStateBytes,
            })?
            .ok_or_else(|| de::Error::invalid_length(2, &self))?;
        let max_steps = sequence
            .next_element::<usize>()?
            .ok_or_else(|| de::Error::invalid_length(3, &self))?;
        if max_steps > MAX_FSM_STEPS {
            return Err(deserialization_limit(
                FsmLimitDimension::Steps,
                MAX_FSM_STEPS,
                max_steps,
            ));
        }
        FsmWorkflow::new(name, initial_state, states, max_steps).map_err(de::Error::custom)
    }
}

#[derive(Default)]
struct DeserializationBudget {
    graph_bytes: usize,
    edges: usize,
}

impl DeserializationBudget {
    fn add_text<E>(&mut self, dimension: FsmLimitDimension, value: &str) -> Result<(), E>
    where
        E: de::Error,
    {
        let observed = value.len();
        let limit = text_limit(dimension);
        if observed > limit {
            return Err(deserialization_limit(dimension, limit, observed));
        }
        let observed = self.graph_bytes.saturating_add(observed);
        if observed > MAX_FSM_GRAPH_BYTES {
            return Err(deserialization_limit(
                FsmLimitDimension::GraphBytes,
                MAX_FSM_GRAPH_BYTES,
                observed,
            ));
        }
        self.graph_bytes = observed;
        Ok(())
    }

    fn add_edge<E>(&mut self) -> Result<(), E>
    where
        E: de::Error,
    {
        let observed = self.edges.saturating_add(1);
        if observed > MAX_FSM_EDGES {
            return Err(deserialization_limit(
                FsmLimitDimension::Edges,
                MAX_FSM_EDGES,
                observed,
            ));
        }
        self.edges = observed;
        Ok(())
    }
}

fn text_limit(dimension: FsmLimitDimension) -> usize {
    match dimension {
        FsmLimitDimension::ActionBytes => MAX_FSM_ACTION_BYTES,
        FsmLimitDimension::OutcomeBytes => MAX_FSM_OUTCOME_BYTES,
        FsmLimitDimension::WorkflowNameBytes
        | FsmLimitDimension::InitialStateBytes
        | FsmLimitDimension::StateNameBytes
        | FsmLimitDimension::TransitionTargetBytes => MAX_FSM_TEXT_BYTES,
        FsmLimitDimension::Steps
        | FsmLimitDimension::States
        | FsmLimitDimension::Edges
        | FsmLimitDimension::GraphBytes
        | FsmLimitDimension::HistoryBytes => MAX_FSM_TEXT_BYTES,
    }
}

fn deserialization_limit<E>(dimension: FsmLimitDimension, limit: usize, observed: usize) -> E
where
    E: de::Error,
{
    E::custom(FsmValidationError::LimitExceeded {
        dimension,
        limit,
        observed,
    })
}

/// Deserialize a state list through the budgeted seed.
///
/// `Vec<FsmState>`'s derived impl never reaches the crate-private visitor
/// that is the only place `MAX_FSM_STATES` is enforced, and it calls
/// `FsmState::deserialize` per element, which starts a fresh budget each
/// time and so turns the graph-byte and edge ceilings into per-state ones.
/// Any request type carrying a bare state list wants
/// `#[serde(deserialize_with = "...deserialize_bounded_states")]` so the
/// refusal happens at parse time instead of after the whole body has been
/// materialized.
pub fn deserialize_bounded_states<'de, D>(deserializer: D) -> Result<Vec<FsmState>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut budget = DeserializationBudget::default();
    StatesSeed {
        budget: &mut budget,
    }
    .deserialize(deserializer)
}

struct StatesSeed<'a> {
    budget: &'a mut DeserializationBudget,
}

impl<'de> DeserializeSeed<'de> for StatesSeed<'_> {
    type Value = Vec<FsmState>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(StatesVisitor {
            budget: self.budget,
        })
    }
}

struct StatesVisitor<'a> {
    budget: &'a mut DeserializationBudget,
}

impl<'de> Visitor<'de> for StatesVisitor<'_> {
    type Value = Vec<FsmState>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded sequence of FSM states")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut states = Vec::new();
        while states.len() < MAX_FSM_STATES {
            match sequence.next_element_seed(StateSeed {
                budget: &mut *self.budget,
            })? {
                Some(state) => states.push(state),
                None => return Ok(states),
            }
        }
        match sequence.next_element_seed(RejectStateSeed {
            observed: states.len().saturating_add(1),
        })? {
            None => Ok(states),
            Some(never) => match never {},
        }
    }
}

struct RejectStateSeed {
    observed: usize,
}

impl<'de> DeserializeSeed<'de> for RejectStateSeed {
    type Value = std::convert::Infallible;

    fn deserialize<D>(self, _deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        Err(deserialization_limit(
            FsmLimitDimension::States,
            MAX_FSM_STATES,
            self.observed,
        ))
    }
}

struct StateSeed<'a> {
    budget: &'a mut DeserializationBudget,
}

impl<'de> DeserializeSeed<'de> for StateSeed<'_> {
    type Value = FsmState;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "FsmState",
            &["name", "action", "transitions"],
            StateVisitor {
                budget: self.budget,
            },
        )
    }
}

struct StateVisitor<'a> {
    budget: &'a mut DeserializationBudget,
}

impl<'de> Visitor<'de> for StateVisitor<'_> {
    type Value = FsmState;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded FSM state")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        #[cfg(test)]
        record_fsm_callsite(FsmCallsiteEvent::StateBodyVisited);
        let mut name = None;
        let mut action = None;
        let mut transitions = None;

        while let Some(field) = map.next_key::<StructuralField>()? {
            match field {
                StructuralField::Name => {
                    if name.is_some() {
                        return Err(de::Error::duplicate_field("name"));
                    }
                    let value = map.next_value_seed(BoundedStringSeed {
                        budget: &mut *self.budget,
                        dimension: FsmLimitDimension::StateNameBytes,
                    })?;
                    name = Some(value);
                }
                StructuralField::Action => {
                    if action.is_some() {
                        return Err(de::Error::duplicate_field("action"));
                    }
                    let value = map.next_value_seed(BoundedStringSeed {
                        budget: &mut *self.budget,
                        dimension: FsmLimitDimension::ActionBytes,
                    })?;
                    action = Some(value);
                }
                StructuralField::Transitions => {
                    if transitions.is_some() {
                        return Err(de::Error::duplicate_field("transitions"));
                    }
                    transitions = Some(map.next_value_seed(TransitionsSeed {
                        budget: &mut *self.budget,
                    })?);
                }
                StructuralField::States
                | StructuralField::InitialState
                | StructuralField::MaxSteps
                | StructuralField::Unknown => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }

        Ok(FsmState {
            name: name.ok_or_else(|| de::Error::missing_field("name"))?,
            action: action.ok_or_else(|| de::Error::missing_field("action"))?,
            transitions: transitions.ok_or_else(|| de::Error::missing_field("transitions"))?,
        })
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        #[cfg(test)]
        record_fsm_callsite(FsmCallsiteEvent::StateBodyVisited);
        let name = sequence
            .next_element_seed(BoundedStringSeed {
                budget: &mut *self.budget,
                dimension: FsmLimitDimension::StateNameBytes,
            })?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let action = sequence
            .next_element_seed(BoundedStringSeed {
                budget: &mut *self.budget,
                dimension: FsmLimitDimension::ActionBytes,
            })?
            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
        let transitions = sequence
            .next_element_seed(TransitionsSeed {
                budget: &mut *self.budget,
            })?
            .ok_or_else(|| de::Error::invalid_length(2, &self))?;
        Ok(FsmState {
            name,
            action,
            transitions,
        })
    }
}

struct TransitionsSeed<'a> {
    budget: &'a mut DeserializationBudget,
}

impl<'de> DeserializeSeed<'de> for TransitionsSeed<'_> {
    type Value = HashMap<String, String>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(TransitionsVisitor {
            budget: self.budget,
        })
    }
}

struct TransitionsVisitor<'a> {
    budget: &'a mut DeserializationBudget,
}

struct RejectTransitionKeySeed {
    observed: usize,
}

impl<'de> DeserializeSeed<'de> for RejectTransitionKeySeed {
    type Value = std::convert::Infallible;

    fn deserialize<D>(self, _deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        Err(deserialization_limit(
            FsmLimitDimension::Edges,
            MAX_FSM_EDGES,
            self.observed,
        ))
    }
}

impl<'de> Visitor<'de> for TransitionsVisitor<'_> {
    type Value = HashMap<String, String>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded FSM transition map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut transitions = HashMap::new();
        while self.budget.edges < MAX_FSM_EDGES {
            let Some(outcome) = map.next_key_seed(BoundedStringSeed {
                budget: &mut *self.budget,
                dimension: FsmLimitDimension::OutcomeBytes,
            })?
            else {
                return Ok(transitions);
            };
            self.budget.add_edge::<A::Error>()?;
            let target = map.next_value_seed(BoundedStringSeed {
                budget: &mut *self.budget,
                dimension: FsmLimitDimension::TransitionTargetBytes,
            })?;
            transitions.insert(outcome, target);
        }
        match map.next_key_seed(RejectTransitionKeySeed {
            observed: self.budget.edges.saturating_add(1),
        })? {
            None => Ok(transitions),
            Some(never) => match never {},
        }
    }
}

/// The bounded resource dimension rejected by an FSM operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsmLimitDimension {
    /// Maximum transitions retained by an execution.
    Steps,
    /// Maximum states in a workflow graph.
    States,
    /// Maximum transition edges in a workflow graph.
    Edges,
    /// Maximum bytes in the workflow name.
    WorkflowNameBytes,
    /// Maximum bytes in the initial-state name.
    InitialStateBytes,
    /// Maximum bytes in one state name.
    StateNameBytes,
    /// Maximum bytes in one action label.
    ActionBytes,
    /// Maximum bytes in one transition outcome.
    OutcomeBytes,
    /// Maximum bytes in one transition target.
    TransitionTargetBytes,
    /// Maximum aggregate string bytes in a workflow graph.
    GraphBytes,
    /// Maximum aggregate string bytes retained in execution history.
    HistoryBytes,
}

impl fmt::Display for FsmLimitDimension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Steps => "steps",
            Self::States => "states",
            Self::Edges => "edges",
            Self::WorkflowNameBytes => "workflow name bytes",
            Self::InitialStateBytes => "initial state bytes",
            Self::StateNameBytes => "state name bytes",
            Self::ActionBytes => "action bytes",
            Self::OutcomeBytes => "outcome bytes",
            Self::TransitionTargetBytes => "transition target bytes",
            Self::GraphBytes => "graph bytes",
            Self::HistoryBytes => "history bytes",
        };
        formatter.write_str(label)
    }
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
enum FsmCallsiteEvent {
    GraphIndexAllocated { requested_capacity: usize },
    StateBodyVisited,
    StateNameClonedIntoError { bytes: usize },
    TransitionTargetCloned { bytes: usize },
    OutcomeCloned { bytes: usize },
    HistoryPushed { retained_bytes: usize },
}

#[cfg(test)]
std::thread_local! {
    static FSM_CALLSITE_EVENTS: std::cell::RefCell<Option<Vec<FsmCallsiteEvent>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
struct FsmCallsiteProbe {
    previous: Option<Vec<FsmCallsiteEvent>>,
    _current_thread_only: std::marker::PhantomData<std::rc::Rc<()>>,
}

#[cfg(test)]
impl FsmCallsiteProbe {
    fn install_for_current_thread() -> Self {
        let previous = FSM_CALLSITE_EVENTS.with(|events| events.replace(Some(Vec::new())));
        Self {
            previous,
            _current_thread_only: std::marker::PhantomData,
        }
    }

    fn events(&self) -> Vec<FsmCallsiteEvent> {
        FSM_CALLSITE_EVENTS.with(|events| events.borrow().as_ref().cloned().unwrap_or_default())
    }
}

#[cfg(test)]
impl Drop for FsmCallsiteProbe {
    fn drop(&mut self) {
        let previous = self.previous.take();
        FSM_CALLSITE_EVENTS.with(|events| {
            let _ = events.replace(previous);
        });
    }
}

#[cfg(test)]
fn record_fsm_callsite(event: FsmCallsiteEvent) {
    FSM_CALLSITE_EVENTS.with(|events| {
        if let Some(events) = events.borrow_mut().as_mut() {
            events.push(event);
        }
    });
}

/// Structural configuration error for an FSM workflow.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FsmValidationError {
    /// The workflow has no usable name.
    #[error("workflow name must not be empty")]
    EmptyName,
    /// The step/history budget is zero.
    #[error("workflow max_steps must be greater than zero")]
    ZeroStepBudget,
    /// A state name occurs more than once.
    #[error("workflow contains duplicate state {state:?}")]
    DuplicateState {
        /// Repeated state name.
        state: String,
    },
    /// A state has no name.
    #[error("workflow contains a state with an empty name")]
    EmptyStateName,
    /// A state has no action to execute.
    #[error("workflow state {state:?} has an empty action")]
    EmptyAction {
        /// State missing its action.
        state: String,
    },
    /// The declared initial state is absent.
    #[error("workflow initial state {state:?} does not exist")]
    MissingInitialState {
        /// Missing initial-state name.
        state: String,
    },
    /// A transition points to an absent state.
    #[error("workflow state {state:?} outcome {outcome:?} targets missing state {target:?}")]
    MissingTransitionTarget {
        /// State containing the bad edge.
        state: String,
        /// Outcome label for the bad edge.
        outcome: String,
        /// Missing target-state name.
        target: String,
    },
    /// A bounded workflow dimension exceeded its configured maximum.
    #[error("workflow {dimension} limit exceeded: limit {limit}, observed {observed}")]
    LimitExceeded {
        /// Resource dimension that was exceeded.
        dimension: FsmLimitDimension,
        /// Configured maximum for the dimension.
        limit: usize,
        /// Requested or observed value.
        observed: usize,
    },
}

impl FsmWorkflow {
    /// Validate and construct a bounded workflow graph.
    pub fn new<'name, 'initial>(
        name: impl Into<Cow<'name, str>>,
        initial_state: impl Into<Cow<'initial, str>>,
        states: Vec<FsmState>,
        max_steps: usize,
    ) -> Result<Self, FsmValidationError> {
        let name = name.into();
        validate_text_limit(FsmLimitDimension::WorkflowNameBytes, &name)?;
        if name.trim().is_empty() {
            return Err(FsmValidationError::EmptyName);
        }
        if max_steps == 0 {
            return Err(FsmValidationError::ZeroStepBudget);
        }
        if max_steps > MAX_FSM_STEPS {
            return Err(FsmValidationError::LimitExceeded {
                dimension: FsmLimitDimension::Steps,
                limit: MAX_FSM_STEPS,
                observed: max_steps,
            });
        }
        let initial_state = initial_state.into();
        validate_text_limit(FsmLimitDimension::InitialStateBytes, &initial_state)?;
        if states.len() > MAX_FSM_STATES {
            return Err(FsmValidationError::LimitExceeded {
                dimension: FsmLimitDimension::States,
                limit: MAX_FSM_STATES,
                observed: states.len(),
            });
        }

        let edge_count = states.iter().fold(0usize, |count, state| {
            count.saturating_add(state.transitions.len())
        });
        if edge_count > MAX_FSM_EDGES {
            return Err(FsmValidationError::LimitExceeded {
                dimension: FsmLimitDimension::Edges,
                limit: MAX_FSM_EDGES,
                observed: edge_count,
            });
        }

        let mut graph_bytes = 0usize;
        add_graph_bytes(&mut graph_bytes, name.len())?;
        add_graph_bytes(&mut graph_bytes, initial_state.len())?;
        for state in &states {
            validate_text_limit(FsmLimitDimension::StateNameBytes, &state.name)?;
            if state.name.trim().is_empty() {
                return Err(FsmValidationError::EmptyStateName);
            }
            validate_text_limit(FsmLimitDimension::ActionBytes, &state.action)?;
            if state.action.trim().is_empty() {
                #[cfg(test)]
                record_fsm_callsite(FsmCallsiteEvent::StateNameClonedIntoError {
                    bytes: state.name.len(),
                });
                return Err(FsmValidationError::EmptyAction {
                    state: state.name.clone(),
                });
            }
            add_graph_bytes(&mut graph_bytes, state.name.len())?;
            add_graph_bytes(&mut graph_bytes, state.action.len())?;
            for (outcome, target) in &state.transitions {
                validate_text_limit(FsmLimitDimension::OutcomeBytes, outcome)?;
                validate_text_limit(FsmLimitDimension::TransitionTargetBytes, target)?;
                add_graph_bytes(&mut graph_bytes, outcome.len())?;
                add_graph_bytes(&mut graph_bytes, target.len())?;
            }
        }

        let mut indexed = HashMap::with_capacity(states.len());
        #[cfg(test)]
        record_fsm_callsite(FsmCallsiteEvent::GraphIndexAllocated {
            requested_capacity: states.len(),
        });
        for state in states {
            let state_name = state.name.clone();
            if indexed.insert(state_name.clone(), state).is_some() {
                return Err(FsmValidationError::DuplicateState { state: state_name });
            }
        }
        if !indexed.contains_key(initial_state.as_ref()) {
            return Err(FsmValidationError::MissingInitialState {
                state: initial_state.into_owned(),
            });
        }
        for state in indexed.values() {
            for (outcome, target) in &state.transitions {
                if !indexed.contains_key(target) {
                    return Err(FsmValidationError::MissingTransitionTarget {
                        state: state.name.clone(),
                        outcome: outcome.clone(),
                        target: target.clone(),
                    });
                }
            }
        }
        let name = name.into_owned();
        let initial_state = initial_state.into_owned();
        Ok(Self {
            name,
            states: indexed,
            initial_state,
            max_steps,
        })
    }

    /// Human-readable workflow name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Maximum transitions/history records allowed in one execution.
    pub fn max_steps(&self) -> usize {
        self.max_steps
    }

    /// Return the current state's configured action.
    pub fn action(&self, state: &str) -> Option<&str> {
        self.states.get(state).map(|state| state.action.as_str())
    }
}

fn validate_text_limit(
    dimension: FsmLimitDimension,
    value: &str,
) -> Result<(), FsmValidationError> {
    let limit = text_limit(dimension);
    if value.len() > limit {
        return Err(FsmValidationError::LimitExceeded {
            dimension,
            limit,
            observed: value.len(),
        });
    }
    Ok(())
}

fn add_graph_bytes(total: &mut usize, bytes: usize) -> Result<(), FsmValidationError> {
    let observed = total.saturating_add(bytes);
    if observed > MAX_FSM_GRAPH_BYTES {
        return Err(FsmValidationError::LimitExceeded {
            dimension: FsmLimitDimension::GraphBytes,
            limit: MAX_FSM_GRAPH_BYTES,
            observed,
        });
    }
    *total = observed;
    Ok(())
}

/// An in-progress execution of a [`FsmWorkflow`].
pub struct FsmExecution {
    workflow: FsmWorkflow,
    current_state: String,
    /// Ordered record of `(state_name, result_label)` pairs that have been
    /// processed.
    history: Vec<(String, String)>,
    retained_history_bytes: usize,
    completed: bool,
}

/// Result of one successful FSM transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsmTransition {
    /// Execution advanced to the named state.
    Advanced(String),
    /// No transition matched, so execution completed.
    Completed,
}

/// Runtime error from a bounded FSM execution.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FsmExecutionError {
    /// A transition was requested after completion.
    #[error("workflow execution is already completed")]
    AlreadyCompleted,
    /// The configured step/history budget was exhausted.
    #[error("workflow exhausted its {max_steps}-step budget")]
    StepLimit {
        /// Configured maximum transitions/history records.
        max_steps: usize,
    },
    /// A bounded execution dimension exceeded its configured maximum.
    #[error("workflow {dimension} limit exceeded: limit {limit}, observed {observed}")]
    LimitExceeded {
        /// Resource dimension that was exceeded.
        dimension: FsmLimitDimension,
        /// Configured maximum for the dimension.
        limit: usize,
        /// Requested or observed value.
        observed: usize,
    },
}

impl FsmExecution {
    /// Start executing `workflow` from its initial state.
    pub fn new(workflow: FsmWorkflow) -> Self {
        let current_state = workflow.initial_state.clone();
        Self {
            workflow,
            current_state,
            history: Vec::new(),
            retained_history_bytes: 0,
            completed: false,
        }
    }

    /// Return the name of the state the execution is currently in.
    pub fn current_state(&self) -> &str {
        &self.current_state
    }

    /// Return the configured action for the current state.
    pub fn current_action(&self) -> &str {
        self.workflow
            .action(&self.current_state)
            .unwrap_or_default()
    }

    /// Advance the FSM by applying `result` to the current state's transition
    /// table.
    ///
    /// Records the `(current_state, result)` pair in history, then:
    /// - Returns [`FsmTransition::Advanced`] if a transition exists.
    /// - Sets [`Self::is_completed`] and returns [`FsmTransition::Completed`]
    ///   if there is no matching transition.
    /// - Returns [`FsmExecutionError::StepLimit`] before history can exceed
    ///   the configured budget.
    pub fn transition(&mut self, result: &str) -> Result<FsmTransition, FsmExecutionError> {
        if self.completed {
            return Err(FsmExecutionError::AlreadyCompleted);
        }
        if self.history.len() >= self.workflow.max_steps {
            self.completed = true;
            return Err(FsmExecutionError::StepLimit {
                max_steps: self.workflow.max_steps,
            });
        }
        if result.len() > MAX_FSM_OUTCOME_BYTES {
            return Err(FsmExecutionError::LimitExceeded {
                dimension: FsmLimitDimension::OutcomeBytes,
                limit: MAX_FSM_OUTCOME_BYTES,
                observed: result.len(),
            });
        }

        let retained_history_bytes = self
            .retained_history_bytes
            .saturating_add(self.current_state.len())
            .saturating_add(result.len());
        if retained_history_bytes > MAX_FSM_HISTORY_BYTES {
            return Err(FsmExecutionError::LimitExceeded {
                dimension: FsmLimitDimension::HistoryBytes,
                limit: MAX_FSM_HISTORY_BYTES,
                observed: retained_history_bytes,
            });
        }

        let next_state = self
            .workflow
            .states
            .get(&self.current_state)
            .and_then(|s| s.transitions.get(result))
            .map(|next| {
                let cloned = String::clone(next);
                #[cfg(test)]
                record_fsm_callsite(FsmCallsiteEvent::TransitionTargetCloned { bytes: next.len() });
                cloned
            });

        let history_state = self.current_state.clone();
        let history_outcome = result.to_string();
        #[cfg(test)]
        record_fsm_callsite(FsmCallsiteEvent::OutcomeCloned {
            bytes: result.len(),
        });
        self.history.push((history_state, history_outcome));
        self.retained_history_bytes = retained_history_bytes;
        #[cfg(test)]
        record_fsm_callsite(FsmCallsiteEvent::HistoryPushed {
            retained_bytes: self.retained_history_bytes,
        });

        if let Some(next) = next_state {
            self.current_state = next;
            Ok(FsmTransition::Advanced(self.current_state.clone()))
        } else {
            self.completed = true;
            Ok(FsmTransition::Completed)
        }
    }

    /// Return `true` if the execution has reached a terminal state.
    pub fn is_completed(&self) -> bool {
        self.completed
    }

    /// Return the ordered history of `(state_name, result_label)` pairs.
    pub fn history(&self) -> &[(String, String)] {
        &self.history
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These literals are the independently derived Group E contract. Keeping
    // them test-local makes the boundary checks catch a production constant
    // being raised without a corresponding memory-budget decision.
    const EXPECTED_MAX_STATES: usize = 256;
    const EXPECTED_MAX_EDGES: usize = 2_048;
    const EXPECTED_MAX_STEPS: usize = 1_024;
    const EXPECTED_MAX_TEXT_BYTES: usize = 256;
    const EXPECTED_MAX_ACTION_BYTES: usize = 512;
    const EXPECTED_MAX_OUTCOME_BYTES: usize = 4_096;
    const EXPECTED_MAX_GRAPH_BYTES: usize = 1024 * 1024;
    const EXPECTED_MAX_HISTORY_BYTES: usize = 1024 * 1024;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum StringRequestKind {
        OwnedString,
        BorrowedStr,
        Identifier,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct StringRequestEvent {
        role: &'static str,
        kind: StringRequestKind,
        bytes: usize,
    }

    enum StringTraceValue {
        String { role: &'static str, value: String },
        Unsigned(u64),
        Sequence(Vec<StringTraceValue>),
        Map(Vec<(StringTraceValue, StringTraceValue)>),
        Unit,
    }

    type StringTraceLog = std::rc::Rc<std::cell::RefCell<Vec<StringRequestEvent>>>;

    struct StringTraceDeserializer {
        value: StringTraceValue,
        trace: StringTraceLog,
    }

    impl StringTraceDeserializer {
        fn visit_string<'de, V>(
            self,
            visitor: V,
            kind: StringRequestKind,
        ) -> Result<V::Value, serde::de::value::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            let Self { value, trace } = self;
            let StringTraceValue::String { role, value } = value else {
                return Err(string_trace_type_error("a string"));
            };
            trace.borrow_mut().push(StringRequestEvent {
                role,
                kind,
                bytes: value.len(),
            });
            match kind {
                StringRequestKind::OwnedString => visitor.visit_string(value),
                StringRequestKind::BorrowedStr | StringRequestKind::Identifier => {
                    visitor.visit_str(&value)
                }
            }
        }
    }

    fn string_trace_type_error(expected: &str) -> serde::de::value::Error {
        <serde::de::value::Error as serde::de::Error>::custom(format!(
            "string-trace fixture expected {expected}"
        ))
    }

    impl<'de> serde::de::Deserializer<'de> for StringTraceDeserializer {
        type Error = serde::de::value::Error;

        fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            let Self { value, trace } = self;
            match value {
                StringTraceValue::String { role, value } => {
                    trace.borrow_mut().push(StringRequestEvent {
                        role,
                        kind: StringRequestKind::OwnedString,
                        bytes: value.len(),
                    });
                    visitor.visit_string(value)
                }
                StringTraceValue::Unsigned(value) => visitor.visit_u64(value),
                StringTraceValue::Sequence(values) => {
                    visitor.visit_seq(StringTraceSequenceAccess {
                        values: values.into_iter(),
                        trace,
                    })
                }
                StringTraceValue::Map(entries) => visitor.visit_map(StringTraceMapAccess {
                    entries: entries.into_iter(),
                    pending_value: None,
                    trace,
                }),
                StringTraceValue::Unit => visitor.visit_unit(),
            }
        }

        fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            self.visit_string(visitor, StringRequestKind::BorrowedStr)
        }

        fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            self.visit_string(visitor, StringRequestKind::OwnedString)
        }

        fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            self.visit_string(visitor, StringRequestKind::Identifier)
        }

        fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            let StringTraceValue::Unsigned(value) = self.value else {
                return Err(string_trace_type_error("an unsigned integer"));
            };
            visitor.visit_u64(value)
        }

        fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            let Self { value, trace } = self;
            let StringTraceValue::Sequence(values) = value else {
                return Err(string_trace_type_error("a sequence"));
            };
            visitor.visit_seq(StringTraceSequenceAccess {
                values: values.into_iter(),
                trace,
            })
        }

        fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            let Self { value, trace } = self;
            let StringTraceValue::Map(entries) = value else {
                return Err(string_trace_type_error("a map"));
            };
            visitor.visit_map(StringTraceMapAccess {
                entries: entries.into_iter(),
                pending_value: None,
                trace,
            })
        }

        fn deserialize_struct<V>(
            self,
            _name: &'static str,
            _fields: &'static [&'static str],
            visitor: V,
        ) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            self.deserialize_any(visitor)
        }

        fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::Visitor<'de>,
        {
            visitor.visit_unit()
        }

        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u128 f32 f64 char bytes byte_buf
            option unit unit_struct newtype_struct tuple tuple_struct enum
        }
    }

    struct StringTraceSequenceAccess {
        values: std::vec::IntoIter<StringTraceValue>,
        trace: StringTraceLog,
    }

    impl<'de> serde::de::SeqAccess<'de> for StringTraceSequenceAccess {
        type Error = serde::de::value::Error;

        fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
        where
            T: serde::de::DeserializeSeed<'de>,
        {
            self.values
                .next()
                .map(|value| {
                    seed.deserialize(StringTraceDeserializer {
                        value,
                        trace: std::rc::Rc::clone(&self.trace),
                    })
                })
                .transpose()
        }

        fn size_hint(&self) -> Option<usize> {
            Some(self.values.len())
        }
    }

    struct StringTraceMapAccess {
        entries: std::vec::IntoIter<(StringTraceValue, StringTraceValue)>,
        pending_value: Option<StringTraceValue>,
        trace: StringTraceLog,
    }

    impl<'de> serde::de::MapAccess<'de> for StringTraceMapAccess {
        type Error = serde::de::value::Error;

        fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
        where
            K: serde::de::DeserializeSeed<'de>,
        {
            let Some((key, value)) = self.entries.next() else {
                return Ok(None);
            };
            self.pending_value = Some(value);
            seed.deserialize(StringTraceDeserializer {
                value: key,
                trace: std::rc::Rc::clone(&self.trace),
            })
            .map(Some)
        }

        fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
        where
            V: serde::de::DeserializeSeed<'de>,
        {
            let value = self
                .pending_value
                .take()
                .ok_or_else(|| string_trace_type_error("a pending map value"))?;
            seed.deserialize(StringTraceDeserializer {
                value,
                trace: std::rc::Rc::clone(&self.trace),
            })
        }

        fn size_hint(&self) -> Option<usize> {
            Some(self.entries.len())
        }
    }

    fn traced_string(role: &'static str, value: impl Into<String>) -> StringTraceValue {
        StringTraceValue::String {
            role,
            value: value.into(),
        }
    }

    fn deserialize_with_string_trace(
        value: StringTraceValue,
    ) -> (
        Result<FsmWorkflow, serde::de::value::Error>,
        Vec<StringRequestEvent>,
    ) {
        let trace = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let result = FsmWorkflow::deserialize(StringTraceDeserializer {
            value,
            trace: std::rc::Rc::clone(&trace),
        });
        let events = trace.borrow().clone();
        (result, events)
    }

    /// One traced map fixture, named rather than positional.
    ///
    /// Six of the eight fields are `String` and every call site varies
    /// exactly one of them against the same minimal valid workflow, so a
    /// positional argument list made a transposition invisible: `"w", "s",
    /// "s", "a", "go", "s"` reads the same whichever two are swapped.
    /// `Default` carries that base and each case names only what it is
    /// about.
    struct TracedMapWorkflow {
        workflow_name: String,
        initial_state: String,
        state_name: String,
        action: String,
        outcome: String,
        target: String,
        root_unknown_key: Option<String>,
        state_unknown_key: Option<String>,
    }

    impl Default for TracedMapWorkflow {
        fn default() -> Self {
            Self {
                workflow_name: "w".to_string(),
                initial_state: "s".to_string(),
                state_name: "s".to_string(),
                action: "a".to_string(),
                outcome: "go".to_string(),
                target: "s".to_string(),
                root_unknown_key: None,
                state_unknown_key: None,
            }
        }
    }

    fn traced_map_workflow(fixture: TracedMapWorkflow) -> StringTraceValue {
        let TracedMapWorkflow {
            workflow_name,
            initial_state,
            state_name,
            action,
            outcome,
            target,
            root_unknown_key,
            state_unknown_key,
        } = fixture;
        let mut state_entries = Vec::new();
        if let Some(unknown) = state_unknown_key {
            state_entries.push((
                traced_string("state.key.unknown", unknown),
                StringTraceValue::Unit,
            ));
        }
        state_entries.extend([
            (
                traced_string("state.key.name", "name"),
                traced_string("state.name", state_name),
            ),
            (
                traced_string("state.key.action", "action"),
                traced_string("state.action", action),
            ),
            (
                traced_string("state.key.transitions", "transitions"),
                StringTraceValue::Map(vec![(
                    traced_string("transition.outcome", outcome),
                    traced_string("transition.target", target),
                )]),
            ),
        ]);

        let mut root_entries = Vec::new();
        if let Some(unknown) = root_unknown_key {
            root_entries.push((
                traced_string("root.key.unknown", unknown),
                StringTraceValue::Unit,
            ));
        }
        root_entries.extend([
            (
                traced_string("root.key.name", "name"),
                traced_string("root.name", workflow_name),
            ),
            (
                traced_string("root.key.initial_state", "initial_state"),
                traced_string("root.initial_state", initial_state),
            ),
            (
                traced_string("root.key.states", "states"),
                StringTraceValue::Sequence(vec![StringTraceValue::Map(state_entries)]),
            ),
            (
                traced_string("root.key.max_steps", "max_steps"),
                StringTraceValue::Unsigned(1),
            ),
        ]);
        StringTraceValue::Map(root_entries)
    }

    fn traced_sequence_workflow(
        workflow_name: String,
        initial_state: String,
        state_name: String,
        action: String,
        outcome: String,
        target: String,
    ) -> StringTraceValue {
        StringTraceValue::Sequence(vec![
            traced_string("root.sequence.name", workflow_name),
            StringTraceValue::Sequence(vec![StringTraceValue::Sequence(vec![
                traced_string("state.sequence.name", state_name),
                traced_string("state.sequence.action", action),
                StringTraceValue::Map(vec![(
                    traced_string("transition.sequence.outcome", outcome),
                    traced_string("transition.sequence.target", target),
                )]),
            ])]),
            traced_string("root.sequence.initial_state", initial_state),
            StringTraceValue::Unsigned(1),
        ])
    }

    fn traced_workflow_with_edge_count(count: usize) -> StringTraceValue {
        let transitions = (0..count)
            .map(|index| {
                let (outcome_role, target_role) = if index == EXPECTED_MAX_EDGES {
                    ("transition.outcome.overflow", "transition.target.overflow")
                } else {
                    ("transition.outcome.control", "transition.target.control")
                };
                (
                    traced_string(outcome_role, format!("edge-{index:04}")),
                    traced_string(target_role, "s"),
                )
            })
            .collect();
        StringTraceValue::Map(vec![
            (
                traced_string("root.key.name", "name"),
                traced_string("root.name", "edge-admission"),
            ),
            (
                traced_string("root.key.initial_state", "initial_state"),
                traced_string("root.initial_state", "s"),
            ),
            (
                traced_string("root.key.states", "states"),
                StringTraceValue::Sequence(vec![StringTraceValue::Map(vec![
                    (
                        traced_string("state.key.name", "name"),
                        traced_string("state.name", "s"),
                    ),
                    (
                        traced_string("state.key.action", "action"),
                        traced_string("state.action", "agent"),
                    ),
                    (
                        traced_string("state.key.transitions", "transitions"),
                        StringTraceValue::Map(transitions),
                    ),
                ])]),
            ),
            (
                traced_string("root.key.max_steps", "max_steps"),
                StringTraceValue::Unsigned(1),
            ),
        ])
    }

    fn string_role_is_connected_without_ownership(
        events: &[StringRequestEvent],
        role: &'static str,
    ) -> bool {
        let matching = events
            .iter()
            .filter(|event| event.role == role)
            .collect::<Vec<_>>();
        matching.len() == 1
            && matching
                .iter()
                .all(|event| event.kind != StringRequestKind::OwnedString)
    }

    fn traced_limit_case_passes(
        value: StringTraceValue,
        role: &'static str,
        dimension: FsmLimitDimension,
        limit: usize,
        observed: usize,
    ) -> Result<(), String> {
        let expected = FsmValidationError::LimitExceeded {
            dimension,
            limit,
            observed,
        }
        .to_string();
        let (result, events) = deserialize_with_string_trace(value);
        let typed = matches!(&result, Err(error) if error.to_string().contains(&expected));
        let connected_without_ownership = string_role_is_connected_without_ownership(&events, role);
        if typed && connected_without_ownership {
            Ok(())
        } else {
            Err(format!(
                "role={role}, typed={typed}, connected_without_ownership={connected_without_ownership}, result={result:?}, events={events:?}"
            ))
        }
    }

    fn state(name: impl Into<String>, action: impl Into<String>) -> FsmState {
        FsmState {
            name: name.into(),
            action: action.into(),
            transitions: HashMap::new(),
        }
    }

    fn states_with_count(count: usize) -> Vec<FsmState> {
        (0..count)
            .map(|index| state(format!("s{index:03}"), "a"))
            .collect()
    }

    fn states_with_edge_count(count: usize) -> Vec<FsmState> {
        let mut states = states_with_count(EXPECTED_MAX_STATES);
        for edge in 0..count {
            let state_index = edge % EXPECTED_MAX_STATES;
            states[state_index]
                .transitions
                .insert(format!("e{edge:04}"), "s000".to_string());
        }
        states
    }

    fn graph_payload_bytes(workflow_name: &str, initial_state: &str, states: &[FsmState]) -> usize {
        workflow_name.len()
            + initial_state.len()
            + states
                .iter()
                .map(|state| {
                    state.name.len()
                        + state.action.len()
                        + state
                            .transitions
                            .iter()
                            .map(|(outcome, target)| outcome.len() + target.len())
                            .sum::<usize>()
                })
                .sum::<usize>()
    }

    fn states_with_graph_payload_bytes(target_bytes: usize) -> Vec<FsmState> {
        let fixed_bytes = "w".len()
            + "s000".len()
            + EXPECTED_MAX_STATES * ("s000".len() + "a".len())
            + EXPECTED_MAX_EDGES * "s000".len();
        let outcome_bytes = target_bytes
            .checked_sub(fixed_bytes)
            .expect("test graph target must cover fixed graph bytes");
        let short_outcome_len = outcome_bytes / EXPECTED_MAX_EDGES;
        let longer_outcomes = outcome_bytes % EXPECTED_MAX_EDGES;
        assert!(
            short_outcome_len >= "o00000".len()
                && short_outcome_len + usize::from(longer_outcomes > 0)
                    <= EXPECTED_MAX_OUTCOME_BYTES,
            "test graph must keep every outcome inside the per-text limit"
        );

        let mut states = states_with_count(EXPECTED_MAX_STATES);
        for edge in 0..EXPECTED_MAX_EDGES {
            let state_index = edge % EXPECTED_MAX_STATES;
            let local_edge = edge / EXPECTED_MAX_STATES;
            let prefix = format!("o{state_index:03}{local_edge:02}");
            let outcome_len = short_outcome_len + usize::from(edge < longer_outcomes);
            let outcome = format!("{prefix}{}", "x".repeat(outcome_len - prefix.len()));
            states[state_index]
                .transitions
                .insert(outcome, "s000".to_string());
        }
        states
    }

    fn assert_validation_limit(
        result: Result<FsmWorkflow, FsmValidationError>,
        dimension: FsmLimitDimension,
        limit: usize,
        observed: usize,
    ) {
        match result {
            Err(error) => assert_eq!(
                error,
                FsmValidationError::LimitExceeded {
                    dimension,
                    limit,
                    observed,
                }
            ),
            Ok(_) => {
                panic!("workflow limit unexpectedly accepted: limit={limit}, observed={observed}")
            }
        }
    }

    fn assert_constructor_limit(
        name: impl AsRef<str>,
        initial_state: impl AsRef<str>,
        states: Vec<FsmState>,
        max_steps: usize,
        dimension: FsmLimitDimension,
        limit: usize,
        observed: usize,
    ) {
        let probe = FsmCallsiteProbe::install_for_current_thread();
        let result = FsmWorkflow::new(name.as_ref(), initial_state.as_ref(), states, max_steps);
        assert_validation_limit(result, dimension, limit, observed);
        assert!(
            probe.events().is_empty(),
            "constructor allocated its graph index before refusing the quota: {:?}",
            probe.events()
        );
    }

    fn assert_execution_limit(
        result: Result<FsmTransition, FsmExecutionError>,
        dimension: FsmLimitDimension,
        limit: usize,
        observed: usize,
    ) {
        match result {
            Err(error) => assert_eq!(
                error,
                FsmExecutionError::LimitExceeded {
                    dimension,
                    limit,
                    observed,
                }
            ),
            Ok(transition) => panic!(
                "execution limit unexpectedly accepted as {transition:?}: limit={limit}, observed={observed}"
            ),
        }
    }

    #[test]
    fn workflow_accepts_exact_shape_maxima() {
        let graph_states = states_with_graph_payload_bytes(EXPECTED_MAX_GRAPH_BYTES);
        assert_eq!(
            graph_payload_bytes("w", "s000", &graph_states),
            EXPECTED_MAX_GRAPH_BYTES
        );
        let graph = FsmWorkflow::new("w", "s000", graph_states, EXPECTED_MAX_STEPS);
        assert!(
            graph.is_ok(),
            "exact graph maxima must remain usable: {graph:?}"
        );

        let start = "s".repeat(EXPECTED_MAX_TEXT_BYTES);
        let target = "t".repeat(EXPECTED_MAX_TEXT_BYTES);
        let outcome = "o".repeat(EXPECTED_MAX_OUTCOME_BYTES);
        let mut start_state = state(start.clone(), "é".repeat(EXPECTED_MAX_ACTION_BYTES / 2));
        start_state.transitions.insert(outcome, target.clone());
        let exact_text = FsmWorkflow::new(
            "w".repeat(EXPECTED_MAX_TEXT_BYTES),
            start,
            vec![
                start_state,
                state(target, "z".repeat(EXPECTED_MAX_ACTION_BYTES)),
            ],
            EXPECTED_MAX_STEPS,
        );
        assert!(
            exact_text.is_ok(),
            "exact per-text maxima must remain usable: {exact_text:?}"
        );
    }

    #[test]
    fn workflow_rejects_each_shape_max_plus_one() {
        assert_constructor_limit(
            "w",
            "s000",
            states_with_count(1),
            EXPECTED_MAX_STEPS + 1,
            FsmLimitDimension::Steps,
            EXPECTED_MAX_STEPS,
            EXPECTED_MAX_STEPS + 1,
        );
        assert_constructor_limit(
            "w",
            "s000",
            states_with_count(1),
            usize::MAX,
            FsmLimitDimension::Steps,
            EXPECTED_MAX_STEPS,
            usize::MAX,
        );
        assert_constructor_limit(
            "w",
            "s000",
            states_with_count(EXPECTED_MAX_STATES + 1),
            1,
            FsmLimitDimension::States,
            EXPECTED_MAX_STATES,
            EXPECTED_MAX_STATES + 1,
        );
        assert_constructor_limit(
            "w",
            "s000",
            states_with_edge_count(EXPECTED_MAX_EDGES + 1),
            1,
            FsmLimitDimension::Edges,
            EXPECTED_MAX_EDGES,
            EXPECTED_MAX_EDGES + 1,
        );
        assert_constructor_limit(
            "w".repeat(EXPECTED_MAX_TEXT_BYTES + 1),
            "s",
            vec![state("s", "a")],
            1,
            FsmLimitDimension::WorkflowNameBytes,
            EXPECTED_MAX_TEXT_BYTES,
            EXPECTED_MAX_TEXT_BYTES + 1,
        );

        assert_constructor_limit(
            "w",
            "i".repeat(EXPECTED_MAX_TEXT_BYTES + 1),
            vec![state("s", "a")],
            1,
            FsmLimitDimension::InitialStateBytes,
            EXPECTED_MAX_TEXT_BYTES,
            EXPECTED_MAX_TEXT_BYTES + 1,
        );

        let oversized_state = "s".repeat(EXPECTED_MAX_TEXT_BYTES + 1);
        assert_constructor_limit(
            "w",
            "start",
            vec![state("start", "a"), state(oversized_state, "a")],
            1,
            FsmLimitDimension::StateNameBytes,
            EXPECTED_MAX_TEXT_BYTES,
            EXPECTED_MAX_TEXT_BYTES + 1,
        );
        assert_constructor_limit(
            "w",
            "s",
            vec![state("s", "a".repeat(EXPECTED_MAX_ACTION_BYTES + 1))],
            1,
            FsmLimitDimension::ActionBytes,
            EXPECTED_MAX_ACTION_BYTES,
            EXPECTED_MAX_ACTION_BYTES + 1,
        );
        assert_constructor_limit(
            "w",
            "s",
            vec![state(
                "s",
                format!("{}a", "é".repeat(EXPECTED_MAX_ACTION_BYTES / 2)),
            )],
            1,
            FsmLimitDimension::ActionBytes,
            EXPECTED_MAX_ACTION_BYTES,
            EXPECTED_MAX_ACTION_BYTES + 1,
        );

        let mut oversized_outcome_state = state("s", "a");
        oversized_outcome_state
            .transitions
            .insert("o".repeat(EXPECTED_MAX_OUTCOME_BYTES + 1), "s".to_string());
        assert_constructor_limit(
            "w",
            "s",
            vec![oversized_outcome_state],
            1,
            FsmLimitDimension::OutcomeBytes,
            EXPECTED_MAX_OUTCOME_BYTES,
            EXPECTED_MAX_OUTCOME_BYTES + 1,
        );

        let mut oversized_target_state = state("s", "a");
        oversized_target_state
            .transitions
            .insert("ok".to_string(), "t".repeat(EXPECTED_MAX_TEXT_BYTES + 1));
        assert_constructor_limit(
            "w",
            "s",
            vec![oversized_target_state],
            1,
            FsmLimitDimension::TransitionTargetBytes,
            EXPECTED_MAX_TEXT_BYTES,
            EXPECTED_MAX_TEXT_BYTES + 1,
        );

        let oversized_graph = states_with_graph_payload_bytes(EXPECTED_MAX_GRAPH_BYTES + 1);
        assert_eq!(
            graph_payload_bytes("w", "s000", &oversized_graph),
            EXPECTED_MAX_GRAPH_BYTES + 1
        );
        assert_constructor_limit(
            "w",
            "s000",
            oversized_graph,
            1,
            FsmLimitDimension::GraphBytes,
            EXPECTED_MAX_GRAPH_BYTES,
            EXPECTED_MAX_GRAPH_BYTES + 1,
        );
    }

    #[test]
    fn authoritative_edge_quota_accepts_2048_and_refuses_2049() {
        let exact = FsmWorkflow::new("edge-quota", "s000", states_with_edge_count(2_048), 1);
        assert!(exact.is_ok(), "2,048 edges must remain valid: {exact:?}");

        assert_constructor_limit(
            "edge-quota",
            "s000",
            states_with_edge_count(2_049),
            1,
            FsmLimitDimension::Edges,
            2_048,
            2_049,
        );
    }

    #[test]
    fn direct_borrowed_workflow_name_is_rejected_before_string_ownership() {
        let allocator_control = allocation_counter::measure(|| {
            let allocated = std::hint::black_box("allocator-positive-control".repeat(2));
            let _ = std::hint::black_box(&allocated);
        });
        assert!(
            allocator_control.count_total > 0 && allocator_control.bytes_total > 0,
            "the thread-local allocator observer must detect a real heap allocation"
        );

        const OVERSIZED_BYTES: usize = 2 * 1024 * 1024 + 1;
        let oversized = "w".repeat(OVERSIZED_BYTES);
        let states = vec![state("s", "agent")];
        let mut result = None;
        let allocations = allocation_counter::measure(|| {
            result = Some(FsmWorkflow::new(oversized.as_str(), "s", states, 1));
        });
        let result = result.expect("the measured constructor call stores its result");

        assert_validation_limit(
            result,
            FsmLimitDimension::WorkflowNameBytes,
            EXPECTED_MAX_TEXT_BYTES,
            OVERSIZED_BYTES,
        );
        assert_eq!(allocations.count_total, 0);
        assert_eq!(allocations.bytes_total, 0);
        assert_eq!(allocations.count_max, 0);
        assert_eq!(allocations.bytes_max, 0);
    }

    #[test]
    fn direct_constructor_byte_limits_precede_whitespace_validation() {
        assert_constructor_limit(
            " ".repeat(EXPECTED_MAX_TEXT_BYTES + 1),
            "s",
            vec![state("s", "agent")],
            1,
            FsmLimitDimension::WorkflowNameBytes,
            EXPECTED_MAX_TEXT_BYTES,
            EXPECTED_MAX_TEXT_BYTES + 1,
        );
        assert_constructor_limit(
            "workflow",
            " ".repeat(EXPECTED_MAX_TEXT_BYTES + 1),
            vec![state("s", "agent")],
            1,
            FsmLimitDimension::InitialStateBytes,
            EXPECTED_MAX_TEXT_BYTES,
            EXPECTED_MAX_TEXT_BYTES + 1,
        );
        assert_constructor_limit(
            "workflow",
            "s",
            vec![state(" ".repeat(EXPECTED_MAX_TEXT_BYTES + 1), "agent")],
            1,
            FsmLimitDimension::StateNameBytes,
            EXPECTED_MAX_TEXT_BYTES,
            EXPECTED_MAX_TEXT_BYTES + 1,
        );
        assert_constructor_limit(
            "workflow",
            "s",
            vec![state("s", " ".repeat(EXPECTED_MAX_ACTION_BYTES + 1))],
            1,
            FsmLimitDimension::ActionBytes,
            EXPECTED_MAX_ACTION_BYTES,
            EXPECTED_MAX_ACTION_BYTES + 1,
        );
    }

    #[test]
    fn edge_limit_rejects_before_deserializing_the_2049th_outcome_key() {
        let (result, events) =
            deserialize_with_string_trace(traced_workflow_with_edge_count(EXPECTED_MAX_EDGES + 1));
        let expected = FsmValidationError::LimitExceeded {
            dimension: FsmLimitDimension::Edges,
            limit: EXPECTED_MAX_EDGES,
            observed: EXPECTED_MAX_EDGES + 1,
        }
        .to_string();
        let typed_limit = matches!(&result, Err(error) if error.to_string().contains(&expected));
        let control_outcomes = events
            .iter()
            .filter(|event| event.role == "transition.outcome.control")
            .count();
        let control_targets = events
            .iter()
            .filter(|event| event.role == "transition.target.control")
            .count();
        let overflow_body_was_requested = events.iter().any(|event| {
            matches!(
                event.role,
                "transition.outcome.overflow" | "transition.target.overflow"
            )
        });

        assert!(
            typed_limit
                && control_outcomes == EXPECTED_MAX_EDGES
                && control_targets == EXPECTED_MAX_EDGES
                && !overflow_body_was_requested,
            "edge cap consumed the 2,049th key body: typed={typed_limit}, control_outcomes={control_outcomes}, control_targets={control_targets}, events={events:?}"
        );
    }

    #[test]
    fn authoritative_action_quota_accepts_512_and_refuses_513() {
        let exact = FsmWorkflow::new("action-quota", "s", vec![state("s", "a".repeat(512))], 1);
        assert!(
            exact.is_ok(),
            "512 action bytes must remain valid: {exact:?}"
        );

        assert_constructor_limit(
            "action-quota",
            "s",
            vec![state("s", "a".repeat(513))],
            1,
            FsmLimitDimension::ActionBytes,
            512,
            513,
        );
    }

    #[test]
    fn authoritative_outcome_quota_accepts_4096_and_refuses_4097() {
        let mut exact_state = state("s", "a");
        exact_state
            .transitions
            .insert("o".repeat(4_096), "s".to_string());
        let exact = FsmWorkflow::new("outcome-quota", "s", vec![exact_state], 1);
        assert!(
            exact.is_ok(),
            "4,096 outcome bytes must remain valid: {exact:?}"
        );

        let mut oversized_state = state("s", "a");
        oversized_state
            .transitions
            .insert("o".repeat(4_097), "s".to_string());
        assert_constructor_limit(
            "outcome-quota",
            "s",
            vec![oversized_state],
            1,
            FsmLimitDimension::OutcomeBytes,
            4_096,
            4_097,
        );
    }

    #[test]
    fn runtime_outcome_4096_advances_before_4097_transactional_refusal() {
        let exact_outcome = "o".repeat(4_096);
        let oversized_outcome = "p".repeat(4_097);
        let mut looping = state("s", "agent");
        looping
            .transitions
            .insert(exact_outcome.clone(), "s".to_string());
        let workflow = match FsmWorkflow::new("runtime-outcome", "s", vec![looping], 2) {
            Ok(workflow) => workflow,
            Err(error) => panic!("4,096-byte runtime control must validate: {error}"),
        };
        let mut execution = FsmExecution::new(workflow);
        let exact_probe = FsmCallsiteProbe::install_for_current_thread();
        let exact = execution.transition(&exact_outcome);
        let exact_events = exact_probe.events();
        drop(exact_probe);
        assert_eq!(exact, Ok(FsmTransition::Advanced("s".to_string())));
        assert_eq!(
            exact_events,
            vec![
                FsmCallsiteEvent::TransitionTargetCloned { bytes: 1 },
                FsmCallsiteEvent::OutcomeCloned { bytes: 4_096 },
                FsmCallsiteEvent::HistoryPushed {
                    retained_bytes: 4_097,
                },
            ]
        );
        assert_eq!(execution.history(), &[("s".to_string(), exact_outcome)]);

        let state_before = execution.current_state().to_string();
        let history_before = execution.history().to_vec();
        let retained_before = execution.retained_history_bytes;
        let refusal_probe = FsmCallsiteProbe::install_for_current_thread();
        let refusal = execution.transition(&oversized_outcome);
        assert_execution_limit(refusal, FsmLimitDimension::OutcomeBytes, 4_096, 4_097);
        assert!(
            execution.current_state() == state_before
                && execution.history() == history_before.as_slice()
                && execution.retained_history_bytes == retained_before
                && !execution.is_completed()
                && refusal_probe.events().is_empty(),
            "4,097-byte runtime refusal mutated execution: state={:?}, history_len={}, retained={}, completed={}, events={:?}",
            execution.current_state(),
            execution.history().len(),
            execution.retained_history_bytes,
            execution.is_completed(),
            refusal_probe.events()
        );
    }

    #[test]
    fn authoritative_history_quota_accepts_1mib_and_refuses_plus_one() {
        let mut looping = state("s", "agent");
        looping.transitions.insert(String::new(), "s".to_string());
        let workflow = match FsmWorkflow::new("history-quota", "s", vec![looping], 1_024) {
            Ok(workflow) => workflow,
            Err(error) => panic!("history quota control must validate: {error}"),
        };

        // Seed a consistent retained snapshot using only independently valid
        // 256-byte state names and 4,096-byte outcomes. This isolates the
        // history quota from the currently duplicated outcome quota.
        let mut retained = Vec::new();
        for _ in 0..240 {
            retained.push(("s".repeat(256), "o".repeat(4_096)));
        }
        retained.push((String::new(), "r".repeat(4_095)));
        let seeded_bytes = retained
            .iter()
            .map(|(state, outcome)| state.len() + outcome.len())
            .sum::<usize>();
        assert_eq!(seeded_bytes, 1_048_575);

        let mut execution = FsmExecution::new(workflow);
        execution.history = retained;
        execution.retained_history_bytes = seeded_bytes;
        let exact = execution.transition("");
        assert_eq!(exact, Ok(FsmTransition::Advanced("s".to_string())));
        let exact_bytes = execution
            .history()
            .iter()
            .map(|(state, outcome)| state.len() + outcome.len())
            .sum::<usize>();
        assert_eq!(exact_bytes, 1_048_576);
        assert_eq!(execution.retained_history_bytes, 1_048_576);

        let history_before = execution.history().to_vec();
        let probe = FsmCallsiteProbe::install_for_current_thread();
        let first_refusal = execution.transition("");

        assert_execution_limit(
            first_refusal,
            FsmLimitDimension::HistoryBytes,
            1_048_576,
            1_048_577,
        );
        let second_refusal = execution.transition("");
        assert_execution_limit(
            second_refusal,
            FsmLimitDimension::HistoryBytes,
            1_048_576,
            1_048_577,
        );
        assert!(
            !execution.is_completed()
                && execution.current_state() == "s"
                && execution.history() == history_before.as_slice()
                && execution.retained_history_bytes == 1_048_576
                && probe.events().is_empty(),
            "repeated 1 MiB plus one history refusal mutated execution: completed={}, state={:?}, history_len={}, retained={}, events={:?}",
            execution.is_completed(),
            execution.current_state(),
            execution.history().len(),
            execution.retained_history_bytes,
            probe.events()
        );
    }

    #[test]
    fn state_name_limit_precedes_empty_action_without_cloning_oversized_name() {
        let observed_lengths = [
            EXPECTED_MAX_TEXT_BYTES + 1,
            EXPECTED_MAX_GRAPH_BYTES * 2 + 1,
        ];

        for observed in observed_lengths {
            let oversized = FsmState {
                name: "n".repeat(observed),
                action: " \t".to_string(),
                transitions: HashMap::new(),
            };
            let probe = FsmCallsiteProbe::install_for_current_thread();
            let result = FsmWorkflow::new("w", "s", vec![oversized], 1);
            let is_typed_state_name_limit = matches!(
                &result,
                Err(FsmValidationError::LimitExceeded {
                    dimension,
                    limit,
                    observed: actual,
                }) if *dimension == FsmLimitDimension::StateNameBytes
                    && *limit == EXPECTED_MAX_TEXT_BYTES
                    && *actual == observed
            );
            let cloned_name_bytes = probe
                .events()
                .into_iter()
                .filter_map(|event| match event {
                    FsmCallsiteEvent::StateNameClonedIntoError { bytes } => Some(bytes),
                    _ => None,
                })
                .collect::<Vec<_>>();

            assert!(
                is_typed_state_name_limit && cloned_name_bytes.is_empty(),
                "state-name limit lost precedence or cloned the rejected name: observed={observed}, typed={is_typed_state_name_limit}, cloned={cloned_name_bytes:?}"
            );
        }
    }

    #[test]
    fn state_limit_precedes_graph_index_capacity_allocation() {
        let oversized_states = states_with_count(EXPECTED_MAX_STATES + 1);
        let probe = FsmCallsiteProbe::install_for_current_thread();
        let result = FsmWorkflow::new("w", "s000", oversized_states, 1);
        assert_validation_limit(
            result,
            FsmLimitDimension::States,
            EXPECTED_MAX_STATES,
            EXPECTED_MAX_STATES + 1,
        );
        assert!(
            probe.events().is_empty(),
            "graph index capacity was allocated before state validation: {:?}",
            probe.events()
        );
    }

    #[test]
    fn valid_workflow_indexes_only_after_validation_control() {
        let exact_states = states_with_count(EXPECTED_MAX_STATES);
        let probe = FsmCallsiteProbe::install_for_current_thread();
        let result = FsmWorkflow::new("w", "s000", exact_states, 1);
        assert!(
            result.is_ok(),
            "exact state maximum must validate: {result:?}"
        );
        assert_eq!(
            probe.events(),
            vec![FsmCallsiteEvent::GraphIndexAllocated {
                requested_capacity: EXPECTED_MAX_STATES,
            }]
        );
    }

    fn yaml_states_document(states: &[serde_json::Value]) -> String {
        let encoded = match serde_yaml::to_string(states) {
            Ok(encoded) => encoded,
            Err(error) => panic!("sentinel fixture failed to serialize: {error}"),
        };
        let indented = encoded
            .lines()
            .map(|line| format!("  {line}\n"))
            .collect::<String>();
        format!("name: w\ninitial_state: s000\nmax_steps: 1\nstates:\n{indented}")
    }

    fn deserialize_limit_failure(
        yaml: &str,
        dimension: FsmLimitDimension,
        limit: usize,
        observed: usize,
    ) -> Option<String> {
        let expected = FsmValidationError::LimitExceeded {
            dimension,
            limit,
            observed,
        }
        .to_string();
        match serde_yaml::from_str::<FsmWorkflow>(yaml) {
            Err(error) if error.to_string().contains(&expected) => None,
            Err(error) => Some(format!(
                "expected {expected:?} before later sentinel, got {error:?}"
            )),
            Ok(workflow) => Some(format!(
                "expected {expected:?} before later sentinel, accepted {workflow:?}"
            )),
        }
    }

    #[test]
    fn workflow_deserialization_stops_at_each_limit_before_later_sentinel() {
        let oversized_text = "x".repeat(EXPECTED_MAX_TEXT_BYTES + 1);
        let oversized_action = format!("{}a", "é".repeat(EXPECTED_MAX_ACTION_BYTES / 2));
        let oversized_outcome = "o".repeat(EXPECTED_MAX_OUTCOME_BYTES + 1);

        let mut state_count_yaml =
            String::from("name: w\ninitial_state: s000\nmax_steps: 1\nstates:\n");
        for index in 0..=EXPECTED_MAX_STATES {
            state_count_yaml.push_str(&format!(
                "  - name: s{index:03}\n    action: a\n    transitions: {{}}\n"
            ));
        }
        state_count_yaml.push_str(
            "  - name: later-sentinel\n    action: [not-a-string]\n    transitions: {}\n",
        );

        let mut edge_count_yaml = String::from(
            "name: w\ninitial_state: s\nmax_steps: 1\nstates:\n  - name: s\n    action: a\n    transitions:\n",
        );
        for edge in 0..=EXPECTED_MAX_EDGES {
            edge_count_yaml.push_str(&format!("      e{edge:04}: s\n"));
        }
        edge_count_yaml.push_str("      zz_later_sentinel: [not-a-string]\n");

        let graph_states = states_with_graph_payload_bytes(EXPECTED_MAX_GRAPH_BYTES + 1)
            .into_iter()
            .map(|state| {
                serde_json::json!({
                    "name": state.name,
                    "action": state.action,
                    "transitions": state.transitions,
                })
            })
            .chain(std::iter::once(serde_json::json!({
                "name": "later-sentinel",
                "action": ["not-a-string"],
                "transitions": {},
            })))
            .collect::<Vec<_>>();
        let graph_yaml = yaml_states_document(&graph_states);

        let fixtures = vec![
            (
                "steps",
                format!(
                    "name: w\ninitial_state: s\nmax_steps: {}\nstates: later-sentinel\n",
                    EXPECTED_MAX_STEPS + 1
                ),
                FsmLimitDimension::Steps,
                EXPECTED_MAX_STEPS,
                EXPECTED_MAX_STEPS + 1,
            ),
            (
                "workflow name bytes",
                format!(
                    "name: {oversized_text}\ninitial_state: s\nmax_steps: 1\nstates: later-sentinel\n"
                ),
                FsmLimitDimension::WorkflowNameBytes,
                EXPECTED_MAX_TEXT_BYTES,
                EXPECTED_MAX_TEXT_BYTES + 1,
            ),
            (
                "initial state bytes",
                format!(
                    "name: w\ninitial_state: {oversized_text}\nmax_steps: 1\nstates: later-sentinel\n"
                ),
                FsmLimitDimension::InitialStateBytes,
                EXPECTED_MAX_TEXT_BYTES,
                EXPECTED_MAX_TEXT_BYTES + 1,
            ),
            (
                "state name bytes",
                format!(
                    "name: w\ninitial_state: s\nmax_steps: 1\nstates:\n  - name: {oversized_text}\n    action: [later-sentinel]\n    transitions: {{}}\n"
                ),
                FsmLimitDimension::StateNameBytes,
                EXPECTED_MAX_TEXT_BYTES,
                EXPECTED_MAX_TEXT_BYTES + 1,
            ),
            (
                "action bytes",
                format!(
                    "name: w\ninitial_state: s\nmax_steps: 1\nstates:\n  - name: s\n    action: {oversized_action}\n    transitions: later-sentinel\n"
                ),
                FsmLimitDimension::ActionBytes,
                EXPECTED_MAX_ACTION_BYTES,
                EXPECTED_MAX_ACTION_BYTES + 1,
            ),
            (
                "outcome bytes",
                format!(
                    "name: w\ninitial_state: s\nmax_steps: 1\nstates:\n  - name: s\n    action: a\n    transitions:\n      ? {oversized_outcome}\n      : s\n      zz_later_sentinel: [not-a-string]\n"
                ),
                FsmLimitDimension::OutcomeBytes,
                EXPECTED_MAX_OUTCOME_BYTES,
                EXPECTED_MAX_OUTCOME_BYTES + 1,
            ),
            (
                "transition target bytes",
                format!(
                    "name: w\ninitial_state: s\nmax_steps: 1\nstates:\n  - name: s\n    action: a\n    transitions:\n      ok: {oversized_text}\n      zz_later_sentinel: [not-a-string]\n"
                ),
                FsmLimitDimension::TransitionTargetBytes,
                EXPECTED_MAX_TEXT_BYTES,
                EXPECTED_MAX_TEXT_BYTES + 1,
            ),
            (
                "states",
                state_count_yaml,
                FsmLimitDimension::States,
                EXPECTED_MAX_STATES,
                EXPECTED_MAX_STATES + 1,
            ),
            (
                "edges",
                edge_count_yaml,
                FsmLimitDimension::Edges,
                EXPECTED_MAX_EDGES,
                EXPECTED_MAX_EDGES + 1,
            ),
            (
                "aggregate graph bytes",
                graph_yaml,
                FsmLimitDimension::GraphBytes,
                EXPECTED_MAX_GRAPH_BYTES,
                EXPECTED_MAX_GRAPH_BYTES + 1,
            ),
        ];

        let failures = fixtures
            .into_iter()
            .filter_map(|(label, yaml, dimension, limit, observed)| {
                deserialize_limit_failure(&yaml, dimension, limit, observed)
                    .map(|failure| format!("{label}: {failure}"))
            })
            .collect::<Vec<_>>();
        assert!(
            failures.is_empty(),
            "deserializer consumed a later sentinel or reported the wrong typed limit: {failures:#?}"
        );
    }

    #[test]
    fn state_count_limit_precedes_deserializing_the_257th_state_body() {
        let mut yaml = String::from("name: w\ninitial_state: s000\nmax_steps: 1\nstates:\n");
        for index in 0..EXPECTED_MAX_STATES {
            yaml.push_str(&format!(
                "  - name: s{index:03}\n    action: a\n    transitions: {{}}\n"
            ));
        }
        yaml.push_str(&format!(
            "  - name: s256\n    action: {}\n    transitions:\n      later_sentinel: [not-a-string]\n",
            "a".repeat(EXPECTED_MAX_ACTION_BYTES + 1)
        ));

        let expected = FsmValidationError::LimitExceeded {
            dimension: FsmLimitDimension::States,
            limit: EXPECTED_MAX_STATES,
            observed: EXPECTED_MAX_STATES + 1,
        }
        .to_string();
        let probe = FsmCallsiteProbe::install_for_current_thread();
        let result = serde_yaml::from_str::<FsmWorkflow>(&yaml);
        let has_typed_state_limit = matches!(
            &result,
            Err(error) if error.to_string().contains(&expected)
        );
        let visited_state_bodies = probe
            .events()
            .into_iter()
            .filter(|event| matches!(event, FsmCallsiteEvent::StateBodyVisited))
            .count();

        assert!(
            has_typed_state_limit && visited_state_bodies == EXPECTED_MAX_STATES,
            "state cap did not reject before the 257th body: typed={has_typed_state_limit}, visited={visited_state_bodies}"
        );
    }

    #[test]
    fn huge_known_scalar_is_refused_before_application_string_ownership() {
        const HUGE_SCALAR_BYTES: usize = 2 * 1024 * 1024 + 1;

        // The tracing deserializer owns its fixture buffer and records the
        // method requested by the application visitor. This makes no claim
        // about any format scanner's internal buffering.
        let outcome = traced_limit_case_passes(
            traced_map_workflow(TracedMapWorkflow {
                workflow_name: "n".repeat(HUGE_SCALAR_BYTES),
                ..Default::default()
            }),
            "root.name",
            FsmLimitDimension::WorkflowNameBytes,
            256,
            HUGE_SCALAR_BYTES,
        );
        assert!(
            outcome.is_ok(),
            "known scalar ownership failure: {outcome:?}"
        );
    }

    #[test]
    fn huge_unknown_key_is_refused_before_application_string_ownership() {
        const HUGE_UNKNOWN_KEY_BYTES: usize = 2 * 1024 * 1024 + 1;

        let (result, events) =
            deserialize_with_string_trace(traced_map_workflow(TracedMapWorkflow {
                root_unknown_key: Some("u".repeat(HUGE_UNKNOWN_KEY_BYTES)),
                ..Default::default()
            }));
        let connected_without_ownership =
            string_role_is_connected_without_ownership(&events, "root.key.unknown");

        assert!(
            result.is_err() && connected_without_ownership,
            "unknown key was not bounded before application String ownership: result={result:?}, events={events:?}"
        );
    }

    #[test]
    fn map_deserialization_ownership_matrix_is_bounded_and_connected() {
        const MAP_ROLES: [&str; 15] = [
            "root.key.unknown",
            "root.key.name",
            "root.name",
            "root.key.initial_state",
            "root.initial_state",
            "root.key.states",
            "state.key.unknown",
            "state.key.name",
            "state.name",
            "state.key.action",
            "state.action",
            "state.key.transitions",
            "transition.outcome",
            "transition.target",
            "root.key.max_steps",
        ];

        let (control, control_events) =
            deserialize_with_string_trace(traced_map_workflow(TracedMapWorkflow {
                root_unknown_key: Some("root-extra".to_string()),
                state_unknown_key: Some("state-extra".to_string()),
                ..Default::default()
            }));
        let connected = MAP_ROLES
            .iter()
            .all(|role| control_events.iter().any(|event| event.role == *role));
        let owned_control_roles = control_events
            .iter()
            .filter(|event| event.kind == StringRequestKind::OwnedString)
            .map(|event| event.role)
            .collect::<Vec<_>>();

        let limit_failures = vec![
            (
                "workflow name",
                traced_limit_case_passes(
                    traced_map_workflow(TracedMapWorkflow {
                        workflow_name: "w".repeat(257),
                        ..Default::default()
                    }),
                    "root.name",
                    FsmLimitDimension::WorkflowNameBytes,
                    256,
                    257,
                ),
            ),
            (
                "initial state",
                traced_limit_case_passes(
                    traced_map_workflow(TracedMapWorkflow {
                        initial_state: "i".repeat(257),
                        ..Default::default()
                    }),
                    "root.initial_state",
                    FsmLimitDimension::InitialStateBytes,
                    256,
                    257,
                ),
            ),
            (
                "state name",
                traced_limit_case_passes(
                    traced_map_workflow(TracedMapWorkflow {
                        state_name: "n".repeat(257),
                        ..Default::default()
                    }),
                    "state.name",
                    FsmLimitDimension::StateNameBytes,
                    256,
                    257,
                ),
            ),
            (
                "action",
                traced_limit_case_passes(
                    traced_map_workflow(TracedMapWorkflow {
                        action: "a".repeat(513),
                        ..Default::default()
                    }),
                    "state.action",
                    FsmLimitDimension::ActionBytes,
                    512,
                    513,
                ),
            ),
            (
                "outcome",
                traced_limit_case_passes(
                    traced_map_workflow(TracedMapWorkflow {
                        outcome: "o".repeat(4_097),
                        ..Default::default()
                    }),
                    "transition.outcome",
                    FsmLimitDimension::OutcomeBytes,
                    4_096,
                    4_097,
                ),
            ),
            (
                "transition target",
                traced_limit_case_passes(
                    traced_map_workflow(TracedMapWorkflow {
                        target: "t".repeat(257),
                        ..Default::default()
                    }),
                    "transition.target",
                    FsmLimitDimension::TransitionTargetBytes,
                    256,
                    257,
                ),
            ),
        ]
        .into_iter()
        .filter_map(|(label, outcome)| outcome.err().map(|error| (label, error)))
        .collect::<Vec<_>>();

        let structural_failures = [
            (
                "root unknown key",
                traced_map_workflow(TracedMapWorkflow {
                    root_unknown_key: Some("r".repeat(2 * 1024 * 1024 + 1)),
                    ..Default::default()
                }),
                "root.key.unknown",
            ),
            (
                "state unknown key",
                traced_map_workflow(TracedMapWorkflow {
                    state_unknown_key: Some("q".repeat(2 * 1024 * 1024 + 1)),
                    ..Default::default()
                }),
                "state.key.unknown",
            ),
        ]
        .into_iter()
        .filter_map(|(label, value, role)| {
            let (result, events) = deserialize_with_string_trace(value);
            if result.is_err() && string_role_is_connected_without_ownership(&events, role) {
                None
            } else {
                Some((label, result, events))
            }
        })
        .collect::<Vec<_>>();

        assert!(
            control.is_ok()
                && connected
                && owned_control_roles.is_empty()
                && limit_failures.is_empty()
                && structural_failures.is_empty(),
            "map ownership matrix failed: control={control:?}, connected={connected}, owned={owned_control_roles:?}, limits={limit_failures:?}, structural={structural_failures:?}"
        );
    }

    #[test]
    fn sequence_deserialization_ownership_matrix_is_bounded_and_connected() {
        const SEQUENCE_ROLES: [&str; 6] = [
            "root.sequence.name",
            "state.sequence.name",
            "state.sequence.action",
            "transition.sequence.outcome",
            "transition.sequence.target",
            "root.sequence.initial_state",
        ];

        let (control, control_events) = deserialize_with_string_trace(traced_sequence_workflow(
            "w".to_string(),
            "s".to_string(),
            "s".to_string(),
            "a".to_string(),
            "go".to_string(),
            "s".to_string(),
        ));
        let connected = SEQUENCE_ROLES
            .iter()
            .all(|role| control_events.iter().any(|event| event.role == *role));
        let owned_control_roles = control_events
            .iter()
            .filter(|event| event.kind == StringRequestKind::OwnedString)
            .map(|event| event.role)
            .collect::<Vec<_>>();

        let failures = vec![
            traced_limit_case_passes(
                traced_sequence_workflow(
                    "w".repeat(257),
                    "s".to_string(),
                    "s".to_string(),
                    "a".to_string(),
                    "go".to_string(),
                    "s".to_string(),
                ),
                "root.sequence.name",
                FsmLimitDimension::WorkflowNameBytes,
                256,
                257,
            ),
            traced_limit_case_passes(
                traced_sequence_workflow(
                    "w".to_string(),
                    "i".repeat(257),
                    "s".to_string(),
                    "a".to_string(),
                    "go".to_string(),
                    "s".to_string(),
                ),
                "root.sequence.initial_state",
                FsmLimitDimension::InitialStateBytes,
                256,
                257,
            ),
            traced_limit_case_passes(
                traced_sequence_workflow(
                    "w".to_string(),
                    "s".to_string(),
                    "n".repeat(257),
                    "a".to_string(),
                    "go".to_string(),
                    "s".to_string(),
                ),
                "state.sequence.name",
                FsmLimitDimension::StateNameBytes,
                256,
                257,
            ),
            traced_limit_case_passes(
                traced_sequence_workflow(
                    "w".to_string(),
                    "s".to_string(),
                    "s".to_string(),
                    "a".repeat(513),
                    "go".to_string(),
                    "s".to_string(),
                ),
                "state.sequence.action",
                FsmLimitDimension::ActionBytes,
                512,
                513,
            ),
            traced_limit_case_passes(
                traced_sequence_workflow(
                    "w".to_string(),
                    "s".to_string(),
                    "s".to_string(),
                    "a".to_string(),
                    "o".repeat(4_097),
                    "s".to_string(),
                ),
                "transition.sequence.outcome",
                FsmLimitDimension::OutcomeBytes,
                4_096,
                4_097,
            ),
            traced_limit_case_passes(
                traced_sequence_workflow(
                    "w".to_string(),
                    "s".to_string(),
                    "s".to_string(),
                    "a".to_string(),
                    "go".to_string(),
                    "t".repeat(257),
                ),
                "transition.sequence.target",
                FsmLimitDimension::TransitionTargetBytes,
                256,
                257,
            ),
        ]
        .into_iter()
        .filter_map(Result::err)
        .collect::<Vec<_>>();

        assert!(
            control.is_ok()
                && connected
                && owned_control_roles.is_empty()
                && failures.is_empty(),
            "sequence ownership matrix failed: control={control:?}, connected={connected}, owned={owned_control_roles:?}, failures={failures:?}"
        );
    }

    #[test]
    fn workflow_deserialization_accepts_exact_graph_maximum_control() {
        let exact_text = "x".repeat(EXPECTED_MAX_TEXT_BYTES);
        let exact_target = "t".repeat(EXPECTED_MAX_TEXT_BYTES);
        let exact_outcome = "o".repeat(EXPECTED_MAX_OUTCOME_BYTES);
        let exact_utf8 = "é".repeat(EXPECTED_MAX_ACTION_BYTES / 2);
        let exact_scalar_documents = vec![
            (
                "steps",
                format!(
                    "name: w\ninitial_state: s\nmax_steps: {EXPECTED_MAX_STEPS}\nstates:\n  - name: s\n    action: a\n    transitions: {{}}\n"
                ),
            ),
            (
                "workflow name bytes",
                format!(
                    "name: {exact_text}\ninitial_state: s\nmax_steps: 1\nstates:\n  - name: s\n    action: a\n    transitions: {{}}\n"
                ),
            ),
            (
                "initial state bytes",
                format!(
                    "name: w\ninitial_state: {exact_text}\nmax_steps: 1\nstates:\n  - name: {exact_text}\n    action: a\n    transitions: {{}}\n"
                ),
            ),
            (
                "state name bytes",
                format!(
                    "name: w\ninitial_state: s\nmax_steps: 1\nstates:\n  - name: s\n    action: a\n    transitions: {{}}\n  - name: {exact_text}\n    action: a\n    transitions: {{}}\n"
                ),
            ),
            (
                "action bytes",
                format!(
                    "name: w\ninitial_state: s\nmax_steps: 1\nstates:\n  - name: s\n    action: {exact_utf8}\n    transitions: {{}}\n"
                ),
            ),
            (
                "outcome bytes",
                format!(
                    "name: w\ninitial_state: s\nmax_steps: 1\nstates:\n  - name: s\n    action: a\n    transitions:\n      ? {exact_outcome}\n      : s\n"
                ),
            ),
            (
                "transition target bytes",
                format!(
                    "name: w\ninitial_state: s\nmax_steps: 1\nstates:\n  - name: s\n    action: a\n    transitions:\n      ok: {exact_target}\n  - name: {exact_target}\n    action: a\n    transitions: {{}}\n"
                ),
            ),
        ];
        let mut failures = exact_scalar_documents
            .into_iter()
            .filter_map(
                |(label, yaml)| match serde_yaml::from_str::<FsmWorkflow>(&yaml) {
                    Ok(_) => None,
                    Err(error) => Some(format!("{label}: {error}")),
                },
            )
            .collect::<Vec<_>>();

        let graph_states = states_with_graph_payload_bytes(EXPECTED_MAX_GRAPH_BYTES)
            .into_iter()
            .map(|state| {
                serde_json::json!({
                    "name": state.name,
                    "action": state.action,
                    "transitions": state.transitions,
                })
            })
            .collect::<Vec<_>>();
        let yaml = yaml_states_document(&graph_states);
        if let Err(error) = serde_yaml::from_str::<FsmWorkflow>(&yaml) {
            failures.push(format!("states, edges, and aggregate graph bytes: {error}"));
        }
        assert!(
            failures.is_empty(),
            "deserializer rejected an exact configured maximum: {failures:#?}"
        );
    }

    #[test]
    fn workflow_json_and_yaml_round_trip_through_canonical_state_sequence() {
        let workflow = branching_workflow();
        let json = serde_json::to_value(&workflow).expect("valid workflow serializes as JSON");
        let state_names = json
            .get("states")
            .and_then(serde_json::Value::as_array)
            .expect("serialized workflow states use the accepted sequence shape")
            .iter()
            .map(|state| {
                state
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>();
        assert_eq!(state_names, vec!["decide", "failure", "success"]);

        let from_json: FsmWorkflow =
            serde_json::from_value(json.clone()).expect("JSON output must be accepted as input");
        assert_eq!(
            serde_json::to_value(&from_json).expect("round-tripped JSON workflow serializes"),
            json
        );

        let yaml = serde_yaml::to_string(&workflow).expect("valid workflow serializes as YAML");
        let from_yaml: FsmWorkflow =
            serde_yaml::from_str(&yaml).expect("YAML output must be accepted as input");
        assert_eq!(from_yaml.name(), "branching");
        assert_eq!(from_yaml.max_steps(), 8);
        assert_eq!(from_yaml.action("decide"), Some("router"));
        assert_eq!(from_yaml.action("failure"), Some("failure-handler"));
        assert_eq!(from_yaml.action("success"), Some("success-handler"));
    }

    #[test]
    fn oversized_outcome_preserves_execution_state() {
        let mut looping = state("s", "agent");
        looping
            .transitions
            .insert("ok".to_string(), "s".to_string());
        let workflow = match FsmWorkflow::new("runtime-limit", "s", vec![looping], 2) {
            Ok(workflow) => workflow,
            Err(error) => panic!("small workflow must validate: {error}"),
        };
        let mut execution = FsmExecution::new(workflow);
        let oversized = "o".repeat(EXPECTED_MAX_OUTCOME_BYTES + 1);
        let probe = FsmCallsiteProbe::install_for_current_thread();

        let result = execution.transition(&oversized);

        assert_execution_limit(
            result,
            FsmLimitDimension::OutcomeBytes,
            EXPECTED_MAX_OUTCOME_BYTES,
            EXPECTED_MAX_OUTCOME_BYTES + 1,
        );
        assert!(
            execution.current_state() == "s"
                && !execution.is_completed()
                && execution.history().is_empty(),
            "oversized outcome mutated execution: state={:?}, completed={}, history_len={}",
            execution.current_state(),
            execution.is_completed(),
            execution.history().len()
        );
        assert!(
            probe.events().is_empty(),
            "oversized outcome was cloned or committed before rejection: {:?}",
            probe.events()
        );
    }

    #[test]
    fn exhausted_step_budget_precedes_oversized_outcome_without_cloning() {
        let mut looping = state("s", "agent");
        looping
            .transitions
            .insert("ok".to_string(), "s".to_string());
        let workflow = match FsmWorkflow::new("step-precedence", "s", vec![looping], 1) {
            Ok(workflow) => workflow,
            Err(error) => panic!("small workflow must validate: {error}"),
        };
        let mut execution = FsmExecution::new(workflow);
        let first = execution.transition("ok");
        assert_eq!(first, Ok(FsmTransition::Advanced("s".to_string())));
        let state_before = execution.current_state().to_string();
        let history_before = execution.history().to_vec();
        let oversized = "o".repeat(EXPECTED_MAX_OUTCOME_BYTES + 1);
        let probe = FsmCallsiteProbe::install_for_current_thread();

        let result = execution.transition(&oversized);
        let is_step_limit = matches!(
            &result,
            Err(FsmExecutionError::StepLimit { max_steps }) if *max_steps == 1
        );
        let events = probe.events();

        assert!(
            is_step_limit
                && execution.is_completed()
                && execution.current_state() == state_before.as_str()
                && execution.history() == history_before.as_slice()
                && events.is_empty(),
            "step precedence changed or cloned state: step_limit={is_step_limit}, completed={}, state={:?}, history_len={}, events={events:?}",
            execution.is_completed(),
            execution.current_state(),
            execution.history().len()
        );
    }

    #[test]
    fn valid_transition_clones_and_commits_only_after_checks_control() {
        let mut looping = state("s", "agent");
        looping
            .transitions
            .insert("ok".to_string(), "s".to_string());
        let workflow = match FsmWorkflow::new("runtime-control", "s", vec![looping], 2) {
            Ok(workflow) => workflow,
            Err(error) => panic!("small workflow must validate: {error}"),
        };
        let mut execution = FsmExecution::new(workflow);
        let probe = FsmCallsiteProbe::install_for_current_thread();

        let result = execution.transition("ok");

        assert_eq!(result, Ok(FsmTransition::Advanced("s".to_string())));
        let events = probe.events();
        assert_eq!(events.len(), 3, "unexpected transition events: {events:?}");
        assert!(events.contains(&FsmCallsiteEvent::TransitionTargetCloned { bytes: 1 }));
        assert!(events.contains(&FsmCallsiteEvent::OutcomeCloned { bytes: 2 }));
        assert!(events.contains(&FsmCallsiteEvent::HistoryPushed { retained_bytes: 3 }));
    }

    #[test]
    fn retained_history_max_plus_one_preserves_execution_state() {
        let exact_record_outcome = "o".repeat(1_023);
        let overflowing_record_outcome = "p".repeat(1_024);
        let mut looping = state("s", "agent");
        looping
            .transitions
            .insert(exact_record_outcome.clone(), "s".to_string());
        looping
            .transitions
            .insert(overflowing_record_outcome.clone(), "s".to_string());
        let workflow =
            match FsmWorkflow::new("history-limit", "s", vec![looping], EXPECTED_MAX_STEPS) {
                Ok(workflow) => workflow,
                Err(error) => panic!("bounded cycle must validate: {error}"),
            };
        let mut execution = FsmExecution::new(workflow);

        for _ in 0..1_023 {
            if let Err(error) = execution.transition(&exact_record_outcome) {
                panic!("history below the exact byte maximum was rejected: {error}");
            }
        }
        if let Err(error) = execution.transition(&exact_record_outcome) {
            panic!("history at the exact byte maximum was rejected: {error}");
        }
        let retained_bytes = execution
            .history()
            .iter()
            .map(|(state, outcome)| state.len() + outcome.len())
            .sum::<usize>();
        assert_eq!(retained_bytes, EXPECTED_MAX_HISTORY_BYTES);

        let mut overflowing_execution = FsmExecution::new(execution.workflow.clone());
        for _ in 0..1_023 {
            if let Err(error) = overflowing_execution.transition(&exact_record_outcome) {
                panic!("history overflow control setup failed: {error}");
            }
        }
        let history_before = overflowing_execution.history().to_vec();
        let probe = FsmCallsiteProbe::install_for_current_thread();

        let result = overflowing_execution.transition(&overflowing_record_outcome);

        assert_execution_limit(
            result,
            FsmLimitDimension::HistoryBytes,
            EXPECTED_MAX_HISTORY_BYTES,
            EXPECTED_MAX_HISTORY_BYTES + 1,
        );
        assert!(
            overflowing_execution.current_state() == "s"
                && !overflowing_execution.is_completed()
                && overflowing_execution.history() == history_before.as_slice(),
            "history max-plus-one mutated execution: completed={}, history_len={}",
            overflowing_execution.is_completed(),
            overflowing_execution.history().len()
        );
        assert!(
            probe.events().is_empty(),
            "history overflow cloned or pushed before rejection: {:?}",
            probe.events()
        );
    }

    #[test]
    fn constructor_rejects_duplicate_and_missing_transition_targets() {
        let duplicate = FsmState {
            name: "start".to_string(),
            action: "agent".to_string(),
            transitions: [("again".to_string(), "missing".to_string())].into(),
        };
        let error = FsmWorkflow::new(
            "invalid",
            "start",
            vec![
                duplicate,
                FsmState {
                    name: "start".to_string(),
                    action: "other".to_string(),
                    transitions: HashMap::new(),
                },
            ],
            4,
        )
        .unwrap_err();
        assert!(matches!(error, FsmValidationError::DuplicateState { .. }));

        let error = FsmWorkflow::new(
            "invalid-target",
            "start",
            vec![FsmState {
                name: "start".to_string(),
                action: "agent".to_string(),
                transitions: [("again".to_string(), "missing".to_string())].into(),
            }],
            4,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            FsmValidationError::MissingTransitionTarget { .. }
        ));
    }

    #[test]
    fn cyclic_execution_stops_at_the_step_budget_without_growing_history() {
        let workflow = FsmWorkflow::new(
            "cycle",
            "a",
            vec![
                FsmState {
                    name: "a".to_string(),
                    action: "agent-a".to_string(),
                    transitions: [("next".to_string(), "b".to_string())].into(),
                },
                FsmState {
                    name: "b".to_string(),
                    action: "agent-b".to_string(),
                    transitions: [("next".to_string(), "a".to_string())].into(),
                },
            ],
            2,
        )
        .unwrap();
        let mut execution = FsmExecution::new(workflow);
        execution.transition("next").unwrap();
        execution.transition("next").unwrap();
        let error = execution.transition("next").unwrap_err();
        assert!(matches!(
            error,
            FsmExecutionError::StepLimit { max_steps: 2 }
        ));
        assert_eq!(execution.history().len(), 2);
    }

    /// Build a simple linear workflow: start -> middle -> end (terminal).
    fn linear_workflow() -> FsmWorkflow {
        FsmWorkflow::new(
            "linear",
            "start",
            vec![
                FsmState {
                    name: "start".to_string(),
                    action: "agent-a".to_string(),
                    transitions: [("ok".to_string(), "middle".to_string())].into(),
                },
                FsmState {
                    name: "middle".to_string(),
                    action: "agent-b".to_string(),
                    transitions: [("done".to_string(), "end".to_string())].into(),
                },
                FsmState {
                    name: "end".to_string(),
                    action: "agent-c".to_string(),
                    transitions: HashMap::new(), // terminal
                },
            ],
            8,
        )
        .unwrap()
    }

    /// Build a branching workflow: decide -> success OR failure (both terminal).
    fn branching_workflow() -> FsmWorkflow {
        FsmWorkflow::new(
            "branching",
            "decide",
            vec![
                FsmState {
                    name: "decide".to_string(),
                    action: "router".to_string(),
                    transitions: [
                        ("pass".to_string(), "success".to_string()),
                        ("fail".to_string(), "failure".to_string()),
                    ]
                    .into(),
                },
                FsmState {
                    name: "success".to_string(),
                    action: "success-handler".to_string(),
                    transitions: HashMap::new(),
                },
                FsmState {
                    name: "failure".to_string(),
                    action: "failure-handler".to_string(),
                    transitions: HashMap::new(),
                },
            ],
            8,
        )
        .unwrap()
    }

    #[test]
    fn linear_workflow_transitions_correctly() {
        let mut exec = FsmExecution::new(linear_workflow());
        assert_eq!(exec.current_state(), "start");
        assert!(!exec.is_completed());

        let next = exec.transition("ok");
        assert_eq!(next, Ok(FsmTransition::Advanced("middle".to_string())));
        assert_eq!(exec.current_state(), "middle");

        let next = exec.transition("done");
        assert_eq!(next, Ok(FsmTransition::Advanced("end".to_string())));
        assert_eq!(exec.current_state(), "end");

        // Terminal state - no more transitions.
        let next = exec.transition("anything");
        assert_eq!(next, Ok(FsmTransition::Completed));
        assert!(exec.is_completed());
    }

    #[test]
    fn branching_workflow_takes_pass_branch() {
        let mut exec = FsmExecution::new(branching_workflow());
        let next = exec.transition("pass");
        assert_eq!(next, Ok(FsmTransition::Advanced("success".to_string())));
        assert_eq!(exec.current_state(), "success");
    }

    #[test]
    fn branching_workflow_takes_fail_branch() {
        let mut exec = FsmExecution::new(branching_workflow());
        let next = exec.transition("fail");
        assert_eq!(next, Ok(FsmTransition::Advanced("failure".to_string())));
        assert_eq!(exec.current_state(), "failure");
    }

    #[test]
    fn completed_detection_after_terminal() {
        let mut exec = FsmExecution::new(branching_workflow());
        exec.transition("pass").unwrap(); // -> success (terminal)
        assert!(!exec.is_completed()); // success state has no transitions but hasn't been processed yet
        exec.transition("done").unwrap(); // unknown result for success state -> completed
        assert!(exec.is_completed());
    }

    #[test]
    fn unknown_result_marks_completed() {
        let mut exec = FsmExecution::new(linear_workflow());
        let next = exec.transition("unknown_result");
        assert_eq!(next, Ok(FsmTransition::Completed));
        assert!(exec.is_completed());
    }

    #[test]
    fn history_records_all_transitions() {
        let mut exec = FsmExecution::new(linear_workflow());
        exec.transition("ok").unwrap();
        exec.transition("done").unwrap();

        let history = exec.history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0], ("start".to_string(), "ok".to_string()));
        assert_eq!(history[1], ("middle".to_string(), "done".to_string()));
    }

    #[test]
    fn transition_after_completed_returns_typed_error() {
        let mut exec = FsmExecution::new(branching_workflow());
        exec.transition("pass").unwrap();
        exec.transition("done").unwrap(); // completes
        let result = exec.transition("more");
        assert_eq!(result, Err(FsmExecutionError::AlreadyCompleted));
        assert!(exec.is_completed());
    }
}
