package org.lab.sample.jwt.core.rest;

import java.util.List;

import org.lab.sample.jwt.core.model.Pet;
import org.lab.sample.jwt.core.repository.PetRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping(value = "/api/pets")
@Slf4j
public class PetController {

	@Autowired
	private PetRepository repository;

	@GetMapping
	@ResponseBody
	public List<Pet> findAll() {
		log.debug("Searching pets");
		return repository.findAll();
	}

	@PreAuthorize("hasRole('ROLE_Publisher')")
	@PostMapping
	@ResponseBody
	public Pet insert(@RequestBody Pet pet) {
		log.debug("Inserting pet {}", pet);
		repository.insert(pet);
		return pet;
	}

}
