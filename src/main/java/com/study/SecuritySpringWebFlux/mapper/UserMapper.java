package com.study.SecuritySpringWebFlux.mapper;


import com.study.SecuritySpringWebFlux.dto.UserDto;
import com.study.SecuritySpringWebFlux.entity.UserEntity;
import org.mapstruct.InheritInverseConfiguration;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {
    UserDto map(UserEntity userEntity);

    @InheritInverseConfiguration
    UserEntity map(UserDto dto);
}