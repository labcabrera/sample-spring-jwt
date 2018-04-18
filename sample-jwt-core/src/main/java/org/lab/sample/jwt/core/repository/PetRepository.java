package org.lab.sample.jwt.core.repository;

import java.util.ArrayList;
import java.util.List;

import org.lab.sample.jwt.core.model.Pet;
import org.springframework.stereotype.Component;

@Component
public class PetRepository {

	private final List<Pet> values;

	private PetRepository() {
		values = new ArrayList<>();
		values.add(Pet.builder().id("1").name("Chin").build());
		values.add(Pet.builder().id("2").name("Chesco").build());
	}

	public List<Pet> findAll() {
		return values;
	}

}
