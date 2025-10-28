#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::{boxed::Box, vec::Vec};

use crate::noun::Noun;
use crate::tip::{gor_tip, mor_tip, tip_dor_compare};

pub trait ToNoun {
    fn to_noun(&self) -> Noun;
}

impl ToNoun for bool {
    fn to_noun(&self) -> Noun {
        Noun::atom_bool(*self)
    }
}

impl ToNoun for u64 {
    fn to_noun(&self) -> Noun {
        Noun::atom_u64(*self)
    }
}

impl<T: ToNoun> ToNoun for Option<T> {
    fn to_noun(&self) -> Noun {
        match self {
            None => Noun::zero(),
            Some(value) => Noun::cons(Noun::zero(), value.to_noun()),
        }
    }
}

#[derive(Clone)]
pub struct Node<T> {
    pub value: T,
    pub left: Option<Box<Node<T>>>,
    pub right: Option<Box<Node<T>>>,
}

impl<T> Node<T> {
    fn new(value: T) -> Self {
        Self {
            value,
            left: None,
            right: None,
        }
    }
}

#[derive(Clone, Default)]
pub struct ZSet<T> {
    root: Option<Box<Node<T>>>,
}

impl<T: ToNoun + Clone> ZSet<T> {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self { root: None }
    }

    #[allow(dead_code)]
    pub fn insert(&mut self, value: T) {
        let node = self.root.take();
        self.root = Some(insert_node(node, value));
    }

    pub fn root(&self) -> Option<&Box<Node<T>>> {
        self.root.as_ref()
    }
}

impl<T: ToNoun + Clone> From<Vec<T>> for ZSet<T> {
    fn from(values: Vec<T>) -> Self {
        let mut set = ZSet::new();
        for value in values {
            set.insert(value);
        }
        set
    }
}

impl<T: ToNoun + Clone> FromIterator<T> for ZSet<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut set = ZSet::new();
        for value in iter {
            set.insert(value);
        }
        set
    }
}

fn insert_node<T: ToNoun + Clone>(node: Option<Box<Node<T>>>, value: T) -> Box<Node<T>> {
    match node {
        None => Box::new(Node::new(value)),
        Some(mut current) => {
            let node_noun = current.value.to_noun();
            let value_noun = value.to_noun();

            if tip_dor_compare(&value_noun, &node_noun) == core::cmp::Ordering::Equal {
                return current;
            }

            if gor_tip(&value_noun, &node_noun) {
                let left = current.left.take();
                let inserted_left = insert_node(left, value);
                if mor_tip(&current.value.to_noun(), &inserted_left.value.to_noun()) {
                    current.left = Some(inserted_left);
                    current
                } else {
                    let Node {
                        value: child_value,
                        left: child_left,
                        right: child_right,
                    } = *inserted_left;

                    let new_right = Box::new(Node {
                        value: current.value,
                        left: child_right,
                        right: current.right,
                    });

                    Box::new(Node {
                        value: child_value,
                        left: child_left,
                        right: Some(new_right),
                    })
                }
            } else {
                let right = current.right.take();
                let inserted_right = insert_node(right, value);
                if mor_tip(&current.value.to_noun(), &inserted_right.value.to_noun()) {
                    current.right = Some(inserted_right);
                    current
                } else {
                    let Node {
                        value: child_value,
                        left: child_left,
                        right: child_right,
                    } = *inserted_right;

                    let new_left = Box::new(Node {
                        value: current.value,
                        left: current.left,
                        right: child_left,
                    });

                    Box::new(Node {
                        value: child_value,
                        left: Some(new_left),
                        right: child_right,
                    })
                }
            }
        }
    }
}

pub fn zset_to_noun<T: ToNoun + Clone>(node: Option<&Box<Node<T>>>) -> Noun {
    match node {
        None => Noun::zero(),
        Some(node) => {
            let head = node.value.to_noun();
            let left = zset_to_noun(node.left.as_ref());
            let right = zset_to_noun(node.right.as_ref());
            Noun::cons(head, Noun::cons(left, right))
        }
    }
}
